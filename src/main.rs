use ansi_term::Color::{Blue, Cyan, Green, Purple, Red, White, Yellow};
use anyhow::{bail, ensure, Result};
use atty::Stream;
use clap::Parser;
use nix::unistd::{Gid, Group, Uid, User};
use regex::Regex;
use std::fs::{read_link, Metadata};
use std::io::StdoutLock;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::{io::Write, path::Path};
use walkdir::{DirEntry, WalkDir};

#[derive(Parser, Debug)]
#[command(version, max_term_width = 98)]
struct Args {
    /// Show items whose type match this argument (- for files, d for directories, l for
    /// symlinks, p for fifo, s for socket, c for character device, b for block device).
    /// Can be specified multiple times to accept multiple types.
    #[arg(long = "type")]
    etype: Option<Vec<char>>,

    /// Recurse into directories.
    #[arg(short = 'R')]
    recursive: bool,

    /// Show hidden and 'dot' files.
    #[arg(short = 'a')]
    all: bool,

    /// Returns the results that doesn't match instead of the results that does.
    #[arg(long = "invert")]
    invert: bool,

    /// Whether or not rpsc should use colored output (auto, always, never)
    #[arg(long = "colors", default_value = "auto")]
    colors: String,

    /// Specify user permissions using a regex.
    #[arg(short = 'u')]
    user_permissions: Option<String>,

    /// Specify group permissions using a regex.
    #[arg(short = 'g')]
    group_permissions: Option<String>,

    /// Specify public permissions using a regex.
    #[arg(short = 'p')]
    public_permissions: Option<String>,

    /// Specify the user that must own the file.
    #[arg(long = "owner")]
    owner: Option<String>,

    /// Specify the group that must own the file. Not supported on macos.
    #[arg(long = "group")]
    group: Option<String>,

    /// The path of the directory that rpsc should search into.
    #[arg(default_value = ".")]
    path: String,
}

/// # Errors
///
/// Returns an error if the `--group` argument was passed on macos.
/// Returns an error if the path specified in `args.path` is invalid.
/// Returns an error if failed to construct a regex from arguments provided in
/// `args.user_permissions`, `args.group_permissions` or `args.public_permissions`.
/// Some called functions can also returns errors, for reasons explained in their doc comment.
///
///  # Panics
///
///  Some called function can panic, for reasons explained in their doc comment.
fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(target_os = "macos")]
    {
        if args.group.is_some() {
            bail!("The --group argument is not supported on macos")
        }
    }
    ensure!(
        Path::new(&args.path).exists(),
        "\"{}\": No such file or directory (os error 2)",
        args.path
    );
    let user_permissions = match args.user_permissions {
        Some(s) => match Regex::new(&s) {
            Ok(re) => Some(re),
            Err(e) => bail!("\"{s}\": invalid user permissions: {e}"),
        },
        None => None,
    };
    let group_permissions = match args.group_permissions {
        Some(s) => match Regex::new(&s) {
            Ok(re) => Some(re),
            Err(e) => bail!("\"{s}\" invalid group permissions: {e}"),
        },
        None => None,
    };
    let public_permissions = match args.public_permissions {
        Some(s) => match Regex::new(&s) {
            Ok(re) => Some(re),
            Err(e) => bail!("\"{s}\": invalid public permissions: {e}"),
        },
        None => None,
    };

    let colors = match args.colors.as_str() {
        "always" => true,
        "never" => false,
        "auto" => {
            // Colors only if stdout is a tty.
            if atty::is(Stream::Stdout) {
                true
            } else {
                false
            }
        }
        _ => bail!(
            "\"{}\": invalid colors argument (must be auto, always or never)",
            args.colors
        ),
    };

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let walker = construct_walker(args.recursive, &args.path);

    for entry in walker
        .into_iter()
        .filter_entry(|entry| args.all || !is_hidden(entry))
    {
        if entry.is_err() {
            continue; // When we don't have permissions we just skip the entry.
        }
        let entry = entry.unwrap();
        let entry_metadata = entry.metadata();
        if entry_metadata.is_err() {
            continue; // Same as above, we ignore the entry if we don't have permissions.
        }
        let entry_metadata = entry_metadata.unwrap();

        if args.recursive && entry.file_type().is_dir() {
            writeln!(lock, "\n{}:", entry.path().display())?; // Prints the directory we are currently walking.
        }

        let matching = type_matching(&entry, &args.etype.as_deref())?
            && owner_matching(&entry_metadata, &args.owner.as_deref())
            && group_matching(&entry_metadata, &args.group.as_deref())
            && user_permissions_matching(&entry, &entry_metadata, &user_permissions.as_ref())?
            && group_permissions_matching(&entry, &entry_metadata, &group_permissions.as_ref())?
            && public_permissions_matching(&entry, &entry_metadata, &public_permissions.as_ref())?;

        if (!args.invert && matching) || (args.invert && !matching) {
            print_entry(&mut lock, &entry, colors)?;
        }
    }

    Ok(())
}

/// Returns a recursive walker with no max depth if `--recursive is set`, else returns a walker
/// with a max depth of 1.
fn construct_walker(recursive: bool, path: &str) -> WalkDir {
    let walker = WalkDir::new(path).min_depth(1);
    if recursive {
        return walker;
    }
    walker.max_depth(1)
}

/// Returns true if the entry name starts with a dot.
fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/// Determines if the type  of the given entry is matching with one of the given types.
///
/// # Errors
///
/// Returns an error if one of the given types is invalid.
fn type_matching(entry: &DirEntry, etype: &Option<&[char]>) -> Result<bool> {
    if etype.is_none() {
        return Ok(true);
    }

    let mut matching = false;
    for c in etype.as_ref().unwrap().iter() {
        matching = match c {
            'b' => {
                if entry.file_type().is_block_device() {
                    true
                } else {
                    matching
                }
            }
            'c' => {
                if entry.file_type().is_char_device() {
                    true
                } else {
                    matching
                }
            }
            'p' => {
                if entry.file_type().is_fifo() {
                    true
                } else {
                    matching
                }
            }
            's' => {
                if entry.file_type().is_socket() {
                    true
                } else {
                    matching
                }
            }
            '-' => {
                if entry.file_type().is_file() {
                    true
                } else {
                    matching
                }
            }
            'd' => {
                if entry.file_type().is_dir() {
                    true
                } else {
                    matching
                }
            }
            'l' => {
                if entry.file_type().is_symlink() {
                    true
                } else {
                    matching
                }
            }
            _ => bail!(
                "'{}': Invalid type argument (must be '-', 'd', 'l', 'b', 'c', 'p' or 's')",
                c
            ),
        }
    }
    Ok(matching)
}

/// Determines if the owner associated with the given entry is matching with the given owner.
fn owner_matching(entry_metadata: &Metadata, provided_owner: &Option<&str>) -> bool {
    if provided_owner.is_none() {
        return true;
    }

    let owner = User::from_uid(Uid::from(entry_metadata.uid()))
        .unwrap()
        .unwrap();
    if provided_owner.unwrap() == owner.name {
        return true;
    }
    false
}

/// Determines if the group associated with the given entry is matching with the given group.
fn group_matching(entry_metadata: &Metadata, provided_group: &Option<&str>) -> bool {
    if provided_group.is_none() {
        return true;
    }

    let group = Group::from_gid(Gid::from(entry_metadata.uid()))
        .unwrap()
        .unwrap();

    if provided_group.unwrap() == group.name {
        return true;
    }
    false
}

/// Matches the given user permissions against the user permissions of the entry.
fn user_permissions_matching(
    entry: &DirEntry,
    entry_metadata: &Metadata,
    user_permissions: &Option<&Regex>,
) -> Result<bool> {
    if user_permissions.is_none()
        || user_permissions
            .unwrap()
            .is_match(&get_permission_string(entry, entry_metadata)[0..3])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Matches the given group permissions against the group permissions of the entry.
fn group_permissions_matching(
    entry: &DirEntry,
    entry_metadata: &Metadata,
    group_permissions: &Option<&Regex>,
) -> Result<bool> {
    if group_permissions.is_none()
        || group_permissions
            .unwrap()
            .is_match(&get_permission_string(entry, entry_metadata)[3..6])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Matches the given public permissions against the public permissions of the entry.
fn public_permissions_matching(
    entry: &DirEntry,
    entry_metadata: &Metadata,
    public_permissions: &Option<&Regex>,
) -> Result<bool> {
    if public_permissions.is_none()
        || public_permissions
            .unwrap()
            .is_match(&get_permission_string(entry, entry_metadata)[6..9])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Takes a reference to an entry and returns the permissions of the entry as a string of
/// letters and hyphens.
///
/// # Panics
///
/// Panics if one of the number of the numeric permissions of the entry is greater than 7, which
/// should never happen.
fn get_permission_string(entry: &DirEntry, entry_metadata: &Metadata) -> String {
    let mut permissions_code = format!("{:o}", entry_metadata.permissions().mode());

    // Permissions codes have a leading 100 for files, a leading 120 for symlinks and a leading 40
    // for directories. We don't want any of them.
    if entry.file_type().is_dir() {
        for _ in 0..2 {
            permissions_code.remove(0);
        }
    } else {
        for _ in 0..3 {
            permissions_code.remove(0);
        }
    }
    permissions_code
        .chars()
        .map(|c| match c {
            '7' => "rwx",
            '6' => "rw-",
            '5' => "r-x",
            '4' => "r--",
            '3' => "-wx",
            '2' => "-w-",
            '1' => "--x",
            '0' => "---",
            _ => panic!("invalid permission"),
        })
        .collect::<String>()
}

/// Prints the entry file name with different colors depending on it's file type and on
/// the `no_colors` flag.
///
/// # Errors
///
/// Returns an error when failing to write line to stdout.
fn print_entry(lock: &mut StdoutLock, entry: &DirEntry, colors: bool) -> Result<()> {
    let ename = entry.file_name().to_str().unwrap();

    if !colors {
        writeln!(lock, "{}", ename)?;
    } else if entry.file_type().is_block_device() {
        writeln!(lock, "{}", Red.paint(ename))?;
    } else if entry.file_type().is_char_device() {
        writeln!(lock, "{}", Yellow.paint(ename))?;
    } else if entry.file_type().is_socket() {
        writeln!(lock, "{}", Green.paint(ename))?;
    } else if entry.file_type().is_fifo() {
        writeln!(lock, "{}", Purple.paint(ename))?;
    } else if entry.file_type().is_dir() {
        writeln!(lock, "{}", Blue.paint(ename))?;
    } else if entry.file_type().is_symlink() {
        let link = read_link(entry.path()).unwrap();
        let pointing_to = link.to_str().unwrap();
        writeln!(lock, "{} -> {}", Cyan.paint(ename), Cyan.paint(pointing_to))?;
    } else {
        writeln!(lock, "{}", White.paint(ename))?;
    }

    Ok(())
}
