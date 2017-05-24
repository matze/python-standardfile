## Standard File Python client

*Warning*: the decryption is incomplete and is only able to verify that data has
not been tempered with. Actual content decryption is not yet possible.

To test the correctness you can decrypt your remote data with

    python test.py remote --email foo@bar.com --password xyz 

You can print out the master key with 

    python test.py remote --email foo@bar.com --password xyz --show-master-key

and use that to decrypt an encrypted archive with

    python test.py local --file filename.json --key 1234567890...
