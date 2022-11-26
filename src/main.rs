use anyhow::Result;
use atty::Stream;
use clap::{Parser, ValueEnum};
use lscolors::LsColors;
use nix::unistd::{Gid, Group, Uid, User};
use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    fs::{read_link, Metadata},
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use term_grid::{Cell, Direction, Filling, Grid, GridOptions};
use terminal_size::{terminal_size, Height, Width};
use uucore::fs::display_permissions_unix;
use walkdir::{DirEntry, WalkDir};

static TERM_WIDTH: Lazy<usize> =
    Lazy::new(|| terminal_size().unwrap_or((Width(80), Height(0))).0 .0 as usize);

#[derive(Parser, Debug)]
#[command(version, max_term_width = *TERM_WIDTH)]
struct Args {
    /// Specify the type of the items. Can be specified multiple times.
    #[arg(long = "type", value_enum)]
    types: Option<Vec<Type>>,

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

    /// Whether or not rpsc should use colored output.
    #[arg(long = "color", default_value = "auto", value_enum)]
    color: Color,

    /// Specify user permissions using a regex.
    #[arg(short = 'u')]
    user_permissions: Option<Regex>,

    /// Specify group permissions using a regex.
    #[arg(short = 'g')]
    group_permissions: Option<Regex>,

    /// Specify public permissions using a regex.
    #[arg(short = 'p')]
    public_permissions: Option<Regex>,

    /// Specify the user that must own the files.
    #[arg(long = "owner")]
    owner: Option<String>,

    /// Specify the group that must own the files. Not supported on macos.
    #[arg(long = "group", value_parser = |group: &str| {
        #[cfg(target_os = "macos")]
        {
            return Err("This argument is not supported on macos");
        }
        Ok::<std::string::String, &str>(group.to_string())
    })]
    group: Option<String>,

    /// Specify that the files must have extended attributes. [Conflicts with --no-xattr]
    #[arg(long = "xattr", conflicts_with = "no_xattr")]
    xattr: bool,

    /// Specify that the files must not have extended attributes. [Conflicts with --xattr]
    #[arg(long = "no-xattr", conflicts_with = "xattr")]
    no_xattr: bool,

    /// Specify the number of hardlinks the files must have.
    #[arg(long = "hardlinks")]
    hardlinks: Option<u64>,

    /// The path of the directory that rpsc should search into.
    #[arg(default_value = ".", value_parser = |path: &str| {
        match PathBuf::from(path).exists() {
            true => Ok(path.to_string()),
            false => Err("path does not exists")
        }})]
    path: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Color {
    Always,
    Auto,
    Never,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Type {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    Character,
    Block,
}

/// Represents the configuration of rpsc built using the command line arguments passed by the user.
struct Config {
    path: String,
    color: bool,
    recursive: bool,
    all: bool,
    long: bool,
    invert: bool,
    types: Option<Vec<Type>>,
    user_permissions: Option<Regex>,
    group_permissions: Option<Regex>,
    public_permissions: Option<Regex>,
    owner: Option<String>,
    group: Option<String>,
    hardlinks: Option<u64>,
    xattr: Option<bool>,
}

impl TryFrom<Args> for Config {
    type Error = anyhow::Error;

    /// Constructs a configuration from command line arguments.
    fn try_from(args: Args) -> Result<Self, Self::Error> {
        let color = match args.color {
            Color::Always => true,
            Color::Never => false,
            Color::Auto => {
                atty::is(Stream::Stdout) // Colors only if stdout is a tty.
            }
        };
        let xattr = if args.xattr {
            Some(true)
        } else if args.no_xattr {
            Some(false)
        } else {
            None
        };
        Ok(Self {
            path: args.path,
            color,
            recursive: args.recursive,
            all: args.all,
            long: args.long,
            invert: args.invert,
            types: args.types,
            user_permissions: args.user_permissions,
            group_permissions: args.group_permissions,
            public_permissions: args.public_permissions,
            owner: args.owner,
            group: args.group,
            hardlinks: args.hardlinks,
            xattr,
        })
    }
}

/// Represents a file system item.
struct Item {
    entry: DirEntry,
    metadata: Metadata,
    extra_metadata: ExtraMetadata,
}

impl Item {
    fn new(entry: DirEntry, metadata: Metadata) -> Self {
        let extra_metadata = ExtraMetadata::new(&entry, &metadata);
        Self {
            entry,
            metadata,
            extra_metadata,
        }
    }
}

/// Represents some extra metadata not provided by DirEntry.metadata().
struct ExtraMetadata {
    permission_string: String,
    owner: String,
    group: String,
    has_xattr: bool,
}

impl ExtraMetadata {
    fn new(entry: &DirEntry, metadata: &Metadata) -> Self {
        Self {
            permission_string: display_permissions_unix(
                metadata.permissions().mode().try_into().unwrap(),
                true,
            ),
            owner: Self::get_owner(metadata),
            group: Self::get_group(metadata),
            has_xattr: Self::has_extended_attributes(entry),
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

    fn has_extended_attributes(entry: &DirEntry) -> bool {
        let xattr = xattr::list(entry.path());
        if xattr.is_err() {
            return false;
        } else {
            return xattr.unwrap().peekable().peek().is_some();
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::try_from(args)?;
    let mut stdout = io::stdout().lock();
    let lscolors = LsColors::from_env().unwrap_or_default();

    if !config.recursive {
        display_directory(&config.path, &config, &mut stdout, &lscolors)?;
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

            writeln!(stdout, "\n{}:", item.entry.path().display())?; // Prints the path of the directory
                                                                     // that we are walkding.

            display_directory(
                &item.entry.path().to_path_buf(),
                &config,
                &mut stdout,
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
fn display_directory<T, W>(
    path: &T,
    config: &Config,
    lock: &mut W,
    lscolors: &LsColors,
) -> Result<()>
where
    T: AsRef<Path>,
    W: io::Write,
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
            && public_permissions_matching(&item, &config.public_permissions.as_ref())?
            && hardlinks_matching(&item, &config.hardlinks)
            && xattr_matching(&item, &config.xattr);

        if (!config.invert && matching) || (config.invert && !matching) {
            let entry_name = item.entry.file_name().to_str().unwrap().to_string();
            let mut pointing_to: Option<String> = None;

            if config.long {
                grid.add(Cell::from(format!(
                    "{}{}",
                    item.extra_metadata.permission_string,
                    if item.extra_metadata.has_xattr {
                        "@"
                    } else {
                        ""
                    }
                )));
                grid.add(Cell::from(item.metadata.nlink().to_string()));
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

                if let Some(link) = pointing_to {
                    let pointing_to = link.to_string();
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
        write!(lock, "{}", grid.fit_into_columns(5))?;
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
fn type_matching(item: &Item, types: &Option<&[Type]>) -> Result<bool> {
    if types.is_none() {
        return Ok(true);
    }

    let mut matching = false;
    for c in types.unwrap().iter() {
        matching = match c {
            Type::File => {
                if item.entry.file_type().is_file() {
                    true
                } else {
                    matching
                }
            }
            Type::Directory => {
                if item.entry.file_type().is_dir() {
                    true
                } else {
                    matching
                }
            }
            Type::Symlink => {
                if item.entry.file_type().is_symlink() {
                    true
                } else {
                    matching
                }
            }
            Type::Block => {
                if item.entry.file_type().is_block_device() {
                    true
                } else {
                    matching
                }
            }
            Type::Character => {
                if item.entry.file_type().is_char_device() {
                    true
                } else {
                    matching
                }
            }
            Type::Fifo => {
                if item.entry.file_type().is_fifo() {
                    true
                } else {
                    matching
                }
            }
            Type::Socket => {
                if item.entry.file_type().is_socket() {
                    true
                } else {
                    matching
                }
            }
        }
    }
    Ok(matching)
}

fn owner_matching(item: &Item, provided_owner: &Option<&str>) -> bool {
    if provided_owner.is_none() || provided_owner.unwrap() == item.extra_metadata.owner {
        return true;
    }
    false
}

fn group_matching(item: &Item, provided_group: &Option<&str>) -> bool {
    if provided_group.is_none() || provided_group.unwrap() == item.extra_metadata.group {
        return true;
    }
    false
}

fn user_permissions_matching(item: &Item, user_permissions: &Option<&Regex>) -> Result<bool> {
    if user_permissions.is_none()
        || user_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[1..4])
    {
        return Ok(true);
    }
    Ok(false)
}

fn group_permissions_matching(item: &Item, group_permissions: &Option<&Regex>) -> Result<bool> {
    if group_permissions.is_none()
        || group_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[4..7])
    {
        return Ok(true);
    }
    Ok(false)
}

fn public_permissions_matching(item: &Item, public_permissions: &Option<&Regex>) -> Result<bool> {
    if public_permissions.is_none()
        || public_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[7..10])
    {
        return Ok(true);
    }
    Ok(false)
}

fn hardlinks_matching(item: &Item, hardlinks: &Option<u64>) -> bool {
    if hardlinks.is_none() || hardlinks.unwrap() == item.metadata.nlink() {
        return true;
    }
    false
}

fn xattr_matching(item: &Item, xattr: &Option<bool>) -> bool {
    if xattr.is_none() || xattr.unwrap() == item.extra_metadata.has_xattr {
        return true;
    }
    false
}
