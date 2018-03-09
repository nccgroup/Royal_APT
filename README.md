# Royal_APT
Royal APT - APT15 - Related Information from NCC Group Cyber Defense Operations Research


## Decoding scripts
Decoder scripts for BS2005 and RoyalCLI samples found by NCC Group can be found in the scripts directory. 

### BS2005
  `bs_decoder.py` will extract and decrypt commands included in html files sent to the sample `6ea9cc475d41ca07fa206eb84b10cf2bbd2392366890de5ae67241afa2f4269f`; namely `Alive.htm` and `Contents.htm`. It will also decode beacons sent to the C2.

Usage:

`bs2005_decoder.py html <htmlPath>/<htmlsDir>`

`bs2005_decoder.py beacon <beaconString>`

### RoyalCLI
`rcli_decoder.py` will decode RoyalCli config, RoyalCli html commands and the uris. 


Usage:

`royalcli_decoder.py html <htmlPath>/<htmlsDir>`

`royalcli_decoder.py cfg <configPath>`

`royalcli_decoder.py uri <beaconString>`
`

## Yara signatures
Yara signatures for the RoyalCLI, RoyalDNS and BS2005 samples found by NCC Group can be found in `apt15.yara` in the signatures folder.
