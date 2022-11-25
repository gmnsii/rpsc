<div align="center">

# rpsc

rpsc is a \*nix command line tool to quickly search for file systems items matching given permissions criterions.

**Contents:** [Examples](#examples) — [Usage](#usage) — [Installation](#installation) — [Styling](#styling) — [License](#license)

</div>

## Examples

```shell   
$ exa -l
.rw-r--r--   12k dev 23 Nov 16:02 Cargo.lock
.rw-r--r--   360 dev 23 Nov 18:45 Cargo.toml
.rw-r--r--   11k dev 23 Nov 18:43 LICENSE-APACHE
.rw-r--r--  1.1k dev 23 Nov 18:43 LICENSE-MIT
.rw-r--r--   854 dev 24 Nov 09:14 README.md
drwxr-xr-x     - dev 22 Nov 15:17 src
drwxr-xr-x@    - dev 23 Nov 14:37 target

$ rpsc -p r-x
drwxr-xr-x dev target
drwxr-xr-x dev src
```
Here the -p r-x argument mean we want files whose public permissions match the `r-x` regex.
rpsc is not limited to permissions and you can also search files based on their type and on their associated owner and group.
More examples are available in the examples folder in the root of this repository.

## Usage 

Run
```shell
rpsc --help
```
to see a list of commands and their usage.

## Installation

As of now, building rpsc from source is the only way to install it:
```shell
git clone https://github.com/gmnsii/rpsc && cd rpsc && cargo build --release && sudo mv ./target/release/rpsc /usr/local/bin/ && cd .. && rm -rf rpsc
```

## Styling
You can set the colors via the `LS_COLORS` environment variable, like you would for ls or exa. We won't go into too many details here as there is already documentation on how to use this variable available online.

## License

This project is licensed under both :

* The Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* The MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)
