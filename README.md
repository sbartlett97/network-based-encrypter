# Network Based encrypter

This is project is an exercise in curiosity based on networks and encryptioon.

The basic premise is to have a program that scans a network for all responding hosts. From this table of responses it will combine all of the MAC addresses to generate a passphrase that is then hashed. This hash is then used as the key for an encryption function.

From this it should be possible to either add/remove a device from the network for the data to be unrecoverable. 

This will make it possible to securely encrypt documents/data based off of attatched network devices where there is at least one 'keystone' device that when connected/disconected allows the encryption to be reversed.

[![CodeQL](https://github.com/sbartlett97/network-based-encrypter/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/sbartlett97/network-based-encrypter/actions/workflows/codeql-analysis.yml)
## Note

This project is only really viable for encrypting backups or data that is rarely accessed and has no real application outside of theory or small home networks unless you are happy with the data being unrecovereable, as devices get swapped and upgraded all the time so the physical adddresses attatched to larger networks can change fairly often. It is possible to store the hash used to amke it viable, but at this point the security of the program is reduced as there are ways the hash can be stolen.
