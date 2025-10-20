+++
date = '2024-10-18T00:00:00+02:00'
title = 'Cryptography'
categories = ["school", "it sec"]
tags = ["cryptography", "it sec", "school", "encryption", "openssl", "aes", "rsa"]
+++

> Note: this was converted from PDF to Markdown using pdftotext and manual formatting. The original PDF can be found [here](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex3/Raichle_Fürst_Kryptographie.pdf) along with the [bibliography](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex3/quellen.bib).

---

# Cryptography

**Laboratory Protocol**  
Exercise 3: Cryptography  
{{< figure src="/itsi/y3/ex3/images/mika.jpeg" title="Figure: Wunderbares Gruppenbild" >}}
**Subject:** ITSI|ZIVK  
**Class:** 3AHITN  
**Name:** Stefan Fürst, Marcel Raichle  
**Group Name/Number:** Dumm und Dümmer/7  
**Supervisor:** ZIVK  
**Exercise dates:** 4.10.2024, 11.10.2024, 18.10.2024  
**Submission date:** 7.6.2024

---

## Table of Contents

- [Task Definition](#task-definition)
- [Summary](#summary)
  - [Symmetric Encryption](#symmetric-encryption)
  - [Asymmetric Encryption](#asymmetric-encryption)
  - [Integrity Check](#integrity-check)
- [Exercise Execution](#exercise-execution)
  - [Symmetric Encryption](#symmetric-encryption-1)
    - [Calculate Password for Symmetric Encryption](#calculate-password-for-symmetric-encryption)
    - [Encrypt File Symmetrically with AES256](#encrypt-file-symmetrically-with-aes256)
  - [Asymmetric Encryption](#asymmetric-encryption-1)
  - [Check Integrity](#check-integrity)
- [References](#references)
- [List of Figures](#list-of-figures)

---

## Task Definition

First, we deal with symmetric encryption, where a file is encrypted with a calculated password and then decrypted again. The same password is used for both encryption and decryption to verify and validate the process.

In the second part, asymmetric encryption is covered. A private and public key pair is generated, and the file is encrypted using the public key. This approach simulates a typical encryption procedure where the private key is used for decryption.

Finally, an integrity check is performed using hash values. Several text files are compared with given hash values to ensure that no data changes have occurred. The goal is also to identify a hash value that cannot be assigned to any of the text files.

---

## Summary

### Symmetric Encryption

- A password is calculated from a date and a catalog number.
- The file is encrypted using the openssl tool and the AES256 algorithm. A password must be entered.
- Decryption is also performed with openssl, using the -d flag for decryption.

### Asymmetric Encryption

- A key pair (private and public) is generated.
- The file is encrypted using the public key, the private key is used for decryption.
- The corresponding openssl commands are used for this.

### Integrity Check

- sha256sum is used to create a hash value to check the integrity of the file and ensure that no changes have been made to the file.

---

## Exercise Execution

### Symmetric Encryption

#### Calculate Password for Symmetric Encryption

**Date + Catalog Number**

```
20241004 + 24
2
```

#### Encrypt File Symmetrically with AES256

For this, openssl is used, a cryptographic toolkit [^1].

To encrypt the file with AES256 in this case, aes256 is used as an argument and the -in/-out flags specify the input/output file. After entering the command, a password must be entered.

{{< figure src="/itsi/y3/ex3/images/aes-encrypt.png" title="Figure: AES encryption" >}}

For decryption, the -d flag is used, which stands for decrypt. This and swapping input and output are needed to decrypt the file. When the command is executed, the password is requested.

{{< figure src="/itsi/y3/ex3/images/aes-decrypt.png" title="Figure: AES decryption" >}}

```bash
# encrypt
openssl aes256 -in Raichle.txt -out Raichle.encrypted

# decrypt
openssl aes256 -d -in Raichle.encrypted -out Raichle.txt
```

### Asymmetric Encryption

For asymmetric encryption, a key pair must first be generated. Two commands are needed for this, one for the private and one for the public key.

When creating the public key, the algorithm, key bits and filename are specified.

For encryption, the -encrypt flag is used, along with other flags for key and file input to encrypt the file.

```bash
# generate private key
openssl genpkey -algorithm RSA \
-pkeyopt rsa_keygen_bits:4096 \
-out private-key.pem

# extract public key
openssl pkey -in private-key.pem -out public-key.pem -pubout

# encrypt file
openssl rsautl -encrypt \
-inkey zivk.pem \
-pubin -in Raichle-Fuerst-RSA.txt \
-out Raichle-Fuerst-RSA.txt.zivk.enc
```

### Check Integrity

```bash
# required command
sha256sum <filename>
```

{{< figure src="/itsi/y3/ex3/images/hashes.png" title="Figure: Hashes" >}}

---

## References

*For a full bibliography, see the [original BibTeX file](https://github.com/Stefanistkuhl/goobering/blob/master/itsi/y3/ex3/quellen.bib).*

[^1]: cheat.sh/openssl, October 2024. [link](https://cheat.sh/openssl)

## List of Figures

1. Wunderbares Gruppenbild
2. AES encryption
3. AES decryption
4. Hashes
