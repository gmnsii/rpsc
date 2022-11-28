<div align="center">

# rpsc

rpsc is a \*nix command line tool to quickly search for file systems items matching varied criterions like permissions, extended attributes and much more.

**Contents:** [Examples](#examples) — [Usage](#usage) — [Installation](#installation) — [Styling](#styling) — [License](#license)

</div>

## Is this an alternative to ls/exa ?
Absolutely not, rpsc is a tool for the occasional heavylifting and is not as polished and customizable as ls/exa.

## Example
```shell
$ rpsc /dev --type character -p "^.{6}r-x"  --owner root --time modified --time-style="%Y %d %m %H" -l --match-time="2022 25 11 20"

crw-rw-rw-  1  root  wheel     0  2022 25 11 20  aes_0
crw-------  1  root  wheel     0  2022 25 11 20  afsc_type5
crw-------  1  root  wheel     0  2022 25 11 20  auditpipe
crw-r--r--  1  root  wheel     0  2022 25 11 20  auditsessions
crw-------  1  root  wheel     0  2022 25 11 20  autofs
crw-------  1  root  wheel     0  2022 25 11 20  autofs_control
......
```
Here I searched for all the character devices in my /dev folder whose permissions matched the '^......r-x' regex that are owned by the root user and that were last modified the 25 november of this year between 20 and 21 hour.
Of course this is a very specific example but it was to showcase a few of rpsc's options.


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
This will clone the repo, build rpsc for release, move it to /usr/local/bin (you will be asked for your password) and delete the cloned repo.

## Styling
You can set the colors via the `LS_COLORS` environment variable, like you would for ls or exa. We won't go into too many details here as there is already documentation on how to use this variable available online.

## License

This project is licensed under both :

* The Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* The MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)
