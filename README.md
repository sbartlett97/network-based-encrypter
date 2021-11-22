# Network Based encrypter

This is project is an exercise in curiosity based on networks and encryptioon.

The basic premise is to have a program that scans a network for all responding hosts. From this table of responses it will combine all of the MAC addresses to generate a passphrase that is then hashed. This hash is then used as the key for an encryption function.

From this it should be possible to either add/remove a device from the network for the data to be unrecoverable. 

This will make it possible to securely encrypt documents/data based off of attatched network devices where there is at least one 'keystone' device that when connected/disconected allows the encryption to be reversed.
