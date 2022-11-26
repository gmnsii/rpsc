use anyhow::{bail, ensure, Result};
use atty::Stream;
use clap::Parser;
use lscolors::LsColors;
use nix::unistd::{Gid, Group, Uid, User};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs::{read_link, Metadata};
use std::io::StdoutLock;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::{io::Write, path::Path};
use term_grid::{Cell, Direction, Filling, Grid, GridOptions};
use terminal_size::{terminal_size, Height, Width};
use walkdir::{DirEntry, WalkDir};

static TERM_WIDTH: Lazy<usize> =
    Lazy::new(|| terminal_size().unwrap_or((Width(80), Height(0))).0 .0 as usize);

#[derive(Parser, Debug)]
#[command(version, max_term_width = *TERM_WIDTH)]
struct Args {
    /// Show items whose type match this argument ('.' or '-' for files, 'd' for directories, 'l' for
    /// symlinks, 'p' for fifo, 's' for socket, 'c' for character device, 'b' for block device).
    /// Can be specified multiple times to accept multiple types.
    #[arg(long = "type")]
    types: Option<Vec<char>>,

    /// Recurse into directories.
    #[arg(short = 'R', long = "recurse")]
    recursive: bool,

    /// Show hidden and 'dot' files.
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Display extended details and attributes.
    #[arg(short = 'l', long = "long")]
    long: bool,

    /// Returns the results that doesn't match instead of the results that does.
    #[arg(long = "invert")]
    invert: bool,

    /// Whether or not rpsc should use colored output (auto, always, never)
    #[arg(long = "color", default_value = "auto")]
    color: String,

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

/// Represents the configuration of rpsc built using the command line arguments passed by the user.
struct Config {
    path: String,
    color: bool,
    recursive: bool,
    all: bool,
    long: bool,
    invert: bool,
    types: Option<Vec<char>>,
    user_permissions: Option<Regex>,
    group_permissions: Option<Regex>,
    public_permissions: Option<Regex>,
    owner: Option<String>,
    group: Option<String>,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    /// Constructs a configuration from command line arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the --group flag was passed on macos.
    /// Returns an error if the given path does not exists.
    /// Returns an error if faling to construct a regex from the -u, -g and -p arguments.
    /// Returns an error if an invalid argument was passed for the --color option.
    fn try_from(args: Args) -> Result<Self, Self::Error> {
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
        let color = match args.color.as_str() {
            "always" => true,
            "never" => false,
            "auto" => {
                atty::is(Stream::Stdout) // Colors only if stdout is a tty.
            }
            _ => bail!(
                "\"{}\": invalid colors argument (must be auto, always or never)",
                args.color
            ),
        };
        Ok(Self {
            path: args.path,
            color,
            recursive: args.recursive,
            all: args.all,
            long: args.long,
            invert: args.invert,
            types: args.types,
            user_permissions,
            group_permissions,
            public_permissions,
            owner: args.owner,
            group: args.group,
        })
    }
}

/// Represents a file system item.
struct Item {
    entry: DirEntry,
    metadata: Metadata,
    extra_metadata: ItemMetadata,
}

impl Item {
    fn new(entry: DirEntry, metadata: Metadata) -> Self {
        let extra_metadata = ItemMetadata::new(&entry, &metadata);
        Self {
            entry,
            metadata,
            extra_metadata,
        }
    }
}

/// Represents the metadata of a file system item.
struct ItemMetadata {
    permission_string: String,
    type_char: char,
    owner: String,
    group: String,
}

impl ItemMetadata {
    fn new(entry: &DirEntry, metadata: &Metadata) -> Self {
        Self {
            permission_string: Self::get_permission_string(entry, metadata),
            type_char: Self::get_type_char(entry),
            owner: Self::get_owner(metadata),
            group: Self::get_group(metadata),
        }
    }

    /// Takes a reference to an entry and returns the permissions of the entry as a string of
    /// letters and hyphens.
    fn get_permission_string(entry: &DirEntry, metadata: &Metadata) -> String {
        let mut permissions_code = format!("{:o}", metadata.permissions().mode());

        // Permissions codes have a leading code to indicate file type that we don't want.
        if entry.file_type().is_dir()
            || entry.file_type().is_fifo()
            || entry.file_type().is_block_device()
            || entry.file_type().is_char_device()
        {
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
                _ => unreachable!(),
            })
            .collect::<String>()
    }

    /// Gets the type character used when printing the entry.
    fn get_type_char(entry: &DirEntry) -> char {
        if entry.file_type().is_file() {
            '.'
        } else if entry.file_type().is_dir() {
            'd'
        } else if entry.file_type().is_symlink() {
            'l'
        } else if entry.file_type().is_socket() {
            's'
        } else if entry.file_type().is_fifo() {
            'p'
        } else if entry.file_type().is_block_device() {
            'b'
        } else if entry.file_type().is_char_device() {
            'c'
        } else {
            unreachable!()
        }
    }

    /// Get the name of the owner of the file.
    ///
    /// # Panics
    ///
    /// Panics if failing to get the owner of the file, which should never happen as we check
    /// beforehand that we have the right permissions.
    fn get_owner(metadata: &Metadata) -> String {
        User::from_uid(Uid::from(metadata.uid()))
            .unwrap()
            .unwrap()
            .name
    }

    /// Gets the name of the group associated with the entry. Returns an empty string on macos.
    ///
    /// # Panics
    ///
    /// Panics if failing to get the associated group, which should never happen as we check
    /// beforehand that we have the right permissions.
    #[allow(unreachable_code)]
    #[allow(unused_variables)]
    fn get_group(metadata: &Metadata) -> String {
        #[cfg(target_os = "macos")]
        {
            return String::new();
        }

        Group::from_gid(Gid::from(metadata.gid()))
            .unwrap()
            .unwrap()
            .name
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::try_from(args)?;

    let lscolors = LsColors::from_env().unwrap_or_default();
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();

    if !config.recursive {
        display_directory(&config.path, &config, &mut lock, &lscolors)?;
    } else {
        for entry in WalkDir::new(&config.path)
            .min_depth(1)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| config.all || !is_hidden(entry))
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue, // We just ignore the entry if we don't have the right permissions.
            };
            let metadata = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue, // Same as above, we ignore the entry if we don't have the right
                                    // permissions.
            };
            if !metadata.is_dir() {
                continue; // We skip anything that isn't a directory.
            }

            let item = Item::new(entry, metadata);

            writeln!(lock, "\n{}:", item.entry.path().display())?; // Prints the path of the directory
                                                                   // that we are walkding.

            display_directory(
                &item.entry.path().to_path_buf(),
                &config,
                &mut lock,
                &lscolors,
            )?;
        }
    }

    Ok(())
}

/// Non-recursively walks a directory, puts its contents into a grid and display said grid.
///
/// # Errors
///
/// Returns an error if failed to write the grid to stdout.
fn display_directory<T>(
    path: &T,
    config: &Config,
    lock: &mut StdoutLock,
    lscolors: &LsColors,
) -> Result<()>
where
    T: AsRef<Path>,
{
    let mut grid = Grid::new(GridOptions {
        filling: Filling::Spaces(2),
        direction: Direction::LeftToRight,
    });

    for entry in WalkDir::new(path)
        .min_depth(1)
        .max_depth(1)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| config.all || !is_hidden(entry))
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue, // We just ignore the entry if we don't have the right permissions.
        };
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue, // Same as above, we ignore the entry if we don't have the right
                                // permissions.
        };
        let item = Item::new(entry, metadata);

        let matching = type_matching(&item, &config.types.as_deref())?
            && owner_matching(&item, &config.owner.as_deref())
            && group_matching(&item, &config.group.as_deref())
            && user_permissions_matching(&item, &config.user_permissions.as_ref())?
            && group_permissions_matching(&item, &config.group_permissions.as_ref())?
            && public_permissions_matching(&item, &config.public_permissions.as_ref())?;

        if (!config.invert && matching) || (config.invert && !matching) {
            let entry_name = item.entry.file_name().to_str().unwrap().to_string();
            let mut pointing_to: Option<String> = None;

            if config.long {
                grid.add(Cell::from(format!(
                    "{}{}",
                    item.extra_metadata.type_char, item.extra_metadata.permission_string
                )));
                grid.add(Cell::from(item.extra_metadata.owner));
                grid.add(Cell::from(item.extra_metadata.group));

                if item.entry.file_type().is_symlink() {
                    let link = read_link(item.entry.path()).unwrap();
                    pointing_to = Some(link.to_str().unwrap().to_owned())
                }
            }

            if !config.color {
                grid.add(Cell::from(entry_name));
            } else {
                let colored_name = match lscolors
                    .style_for_path_with_metadata(item.entry.path(), Some(&item.metadata))
                {
                    Some(s) => s.to_nu_ansi_term_style().paint(&entry_name).to_string(),
                    None => entry_name.to_string(),
                };

                if pointing_to.is_some() {
                    let pointing_to = pointing_to.unwrap().to_string();
                    let pointing_to_metadata = match PathBuf::from(&pointing_to).metadata() {
                        Ok(meta) => Some(meta),
                        Err(_) => None,
                    };
                    let colored_link = match lscolors
                        .style_for_path_with_metadata(&pointing_to, pointing_to_metadata.as_ref())
                    {
                        Some(s) => s.to_nu_ansi_term_style().paint(&pointing_to).to_string(),
                        None => pointing_to.to_string(),
                    };
                    grid.add(Cell {
                        contents: format!("{} -> {}", colored_name, colored_link),
                        width: entry_name.len() + 4 + pointing_to.len(),
                    })
                } else {
                    grid.add(Cell {
                        contents: colored_name,
                        width: entry_name.len(), // We need to manually give the width or else the color
                                                 // codes will be counted as part of the width and mess
                                                 // up the display.
                    })
                }
            }
        }
    }
    if !config.long {
        write!(
            lock,
            "{}",
            grid.fit_into_width(*TERM_WIDTH)
                .unwrap_or_else(|| grid.fit_into_columns(1))
        )?;
    } else {
        write!(lock, "{}", grid.fit_into_columns(4))?;
    }
    Ok(())
}

/// Returns true if the entry name starts with a dot.
fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/// Determines if the typeof the given entry is matching with one of the given types.
///
/// # Errors
///
/// Returns an error if one of the given types is invalid.
fn type_matching(item: &Item, types: &Option<&[char]>) -> Result<bool> {
    if types.is_none() {
        return Ok(true);
    }

    let mut matching = false;
    for c in types.unwrap().iter() {
        matching = match c {
            '.' | '-' => {
                if item.entry.file_type().is_file() {
                    true
                } else {
                    matching
                }
            }
            'd' => {
                if item.entry.file_type().is_dir() {
                    true
                } else {
                    matching
                }
            }
            'l' => {
                if item.entry.file_type().is_symlink() {
                    true
                } else {
                    matching
                }
            }
            'b' => {
                if item.entry.file_type().is_block_device() {
                    true
                } else {
                    matching
                }
            }
            'c' => {
                if item.entry.file_type().is_char_device() {
                    true
                } else {
                    matching
                }
            }
            'p' => {
                if item.entry.file_type().is_fifo() {
                    true
                } else {
                    matching
                }
            }
            's' => {
                if item.entry.file_type().is_socket() {
                    true
                } else {
                    matching
                }
            }
            _ => bail!(
                "'{}': Invalid type argument (must be '.', '-', 'd', 'l', 'b', 'c', 'p' or 's')",
                c
            ),
        }
    }
    Ok(matching)
}

/// Determines if the owner associated with the given entry is matching with the given owner.
fn owner_matching(item: &Item, provided_owner: &Option<&str>) -> bool {
    if provided_owner.is_none() || provided_owner.unwrap() == item.extra_metadata.owner {
        return true;
    }
    false
}

/// Determines if the group associated with the given entry is matching with the given group.
fn group_matching(item: &Item, provided_group: &Option<&str>) -> bool {
    if provided_group.is_none() || provided_group.unwrap() == item.extra_metadata.group {
        return true;
    }
    false
}

/// Matches the given user permissions against the user permissions of the entry.
fn user_permissions_matching(item: &Item, user_permissions: &Option<&Regex>) -> Result<bool> {
    if user_permissions.is_none()
        || user_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[0..3])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Matches the given group permissions against the group permissions of the entry.
fn group_permissions_matching(item: &Item, group_permissions: &Option<&Regex>) -> Result<bool> {
    if group_permissions.is_none()
        || group_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[3..6])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Matches the given public permissions against the public permissions of the entry.
fn public_permissions_matching(item: &Item, public_permissions: &Option<&Regex>) -> Result<bool> {
    if public_permissions.is_none()
        || public_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[6..9])
    {
        return Ok(true);
    }
    Ok(false)
}
