---
title: "Padding oracle"
date: 2017-02-10  16:59:25
last_modified_at: 2024-06-04 11:37:10
author: "Pixis"
layout: post
permalink: /padding-oracle/
disqus_identifier: 0000-0000-0000-0018
description: "In this article we'll talk about the padding oracle attack technique, using the padding of a message encrypted via a block cipher in CBC mode."
cover: assets/uploads/2017/02/sc1.png
tags:
  - Crypto
translation:
  fr: 
---

In this article we'll talk about the padding oracle attack technique, using the padding of a message encrypted via a block cipher in CBC mode.

<!--more-->

There are two main families of encryption: symmetric ciphers, for which the same key is used for encryption and decryption, and asymmetric ciphers, which have one key for encryption and another for decryption.

When it comes to symmetric ciphers, data can be encrypted in two ways. There are stream ciphers, meaning data of any length can be encrypted; the data does not need to be split. The other way is block ciphers. In this case, data is split into fixed-size blocks to be encrypted.

Finally, several modes of operation are possible for block ciphers, such as CBC, ECB, CFB, etc.

However, block ciphers raise two questions:

* What happens if the size of the message to encrypt is not a multiple of the block size? So what happens if the last block has a smaller size than the other blocks?
* What happens if, once the plaintext is split, two plaintext blocks are identical? Their encryption must not yield two similar results because from a cryptographic standpoint, an attacker would be able to guess that parts of the plaintext are identical, which is not desirable.

In this article we are going to look at the CBC mode of block ciphers, which addresses the second question.

## How CBC mode works

### Padding

Whereas we talked about the padding used by hash functions in the article on [Hash Length Extension](/hash-length-extension){:target="blank"}, here we will look at a padding technique mostly used in block ciphers, [PKCS](https://en.wikipedia.org/wiki/PKCS){:target="blank"}7, whose operation is described in [RFC 5652](https://tools.ietf.org/html/rfc5652#section-6.3){:target="blank"}.

Let N be the block size in bytes. If M bytes are missing in the last block, we add the character '0xM' M times at the end of the block.

For example, if we have 8-byte blocks and the following plaintext:

`"Love hackndo"`

The split will give:

```
"Love hac"
"kndo"
```

So 4 bytes are missing for the last block "kndo" to be 8 bytes. The padding will then be:

`"kndo\x04\x04\x04\x04"`

In the case where the text size is a multiple of the block size, a full block of padding is added after the plaintext. Indeed, imagine two pieces of plaintext data:

```
# Data 1
"\x41\x42\x41\x42\x41\x42\x41\x42"
"\x43\x44\x43\x44\x43\x44\x43\x01"

# Data 2
"\x41\x42\x41\x42\x41\x42\x41\x42"
"\x43\x44\x43\x44\x43\x44\x43"
```

In the first plaintext, the \x01 is part of the information to transmit. If no padding were added, we wouldn't be able to differentiate data 1 from data 2 after padding. Adding a full block thus enables differentiating these cases.

After padding, we have:

```
# Data 1 after padding
"\x41\x42\x41\x42\x41\x42\x41\x42"
"\x43\x44\x43\x44\x43\x44\x43\x01"
"\x08\x08\x08\x08\x08\x08\x08\x08"

# Data 2 after padding
"\x41\x42\x41\x42\x41\x42\x41\x42"
"\x43\x44\x43\x44\x43\x44\x43\x01"
```

The two plaintexts after padding are different, which will give different ciphertexts, which is what we want since the initial data is different.

Here is a little Python code with two functions. One adds the padding required to the last block, and the other removes the padding.

```python
def set_padding(data, size_block=128):
    if size_block % 8 != 0:
        return False
    size_block_byte = size_block/8
    padding = size_block_byte - (len(data) % size_block_byte)
    data += chr(padding)*padding

    return data

def del_padding(data):
    return data[:-ord(data[-1])]

# Example

data = "Love hackndo!"
data_padded = set_padding(data, 64)
print([data_padded])
# >>> ['Love hackndo!\x03\x03\x03']

data_padding_removed = del_padding(data_padded)
print([data_padding_removed])
# >>> ['Love hackndo!']

data = "12345678"
data_padded = set_padding(data, 64)
print([data_padded])
# >>> ['12345678\x08\x08\x08\x08\x08\x08\x08\x08']

data_padding_removed = del_padding(data_padded)
print([data_padding_removed])
# >>> ['12345678']
```

We talk about a padding oracle not in relation to Oracle the company, but because the oracle is the (often) server-side party that gives information about the validity - or not - of the padding of an encrypted message, allowing the attack we are going to talk about next.

### Similar blocks

CBC mode addresses the problem of similar blocks. Imagine we have 32-bit blocks, and the message we want to encode is the following: "hack, or do not hack". By splitting this message into 32-bit blocks (so 4 bytes), we get these 5 blocks:

```
"hack"
", or"
" do "
"not "
"hack"
```

If each block is encrypted independently, then the first and last blocks of our message will give the same ciphertext, which is not desirable as previously indicated.

In CBC mode, to obtain the encryption of a plaintext block, this plaintext is XORed with the ciphertext of the previous block, before being itself encrypted.

We then have:

```
ciphertext_n = encrypt(plaintext_n ⊕ ciphertext_n-1)
```

If you've understood this principle, you should wonder what happens for encrypting the first block, since there is no block before it to perform this XOR.

Well, for that, an IV (**I**nitialization **V**ector) is defined, that is to say a random string chosen for this encryption with a size equal to the block size. This IV simulates a previous block. You then get the following diagram:

[![CBC encryption](/assets/uploads/2017/02/sc1.png)](/assets/uploads/2017/02/sc1.png)

In mathematical terms, here is how CBC encryption works:

```
# For n = 0:

ciphertext_n = encrypt(plaintext_n ⊕ IV)

# For n > 0:

ciphertext_n = encrypt(plaintext_n ⊕ ciphertext_n-1)
```

Thanks to the properties of the XOR operation, here is what decryption looks like in mathematical terms:

```
# For n = 0:

plaintext_n = decrypt(ciphertext_n) ⊕ IV

# For n > 0:

plaintext_n = decrypt(ciphertext_n) ⊕ ciphertext_n-1
```

## CBC mode vulnerability

### From encryption to XOR

Now that the math is on our side, we can create and combine some information. Hang in there, follow along, there's nothing magic.

Let's take a theoretical example, a string that, once padded, is 5 blocks of 8 bytes each. The 5 plaintext blocks are `P_1 .. P_5` and the 5 ciphertext blocks are `C_1 .. C_5`.

So we have the following diagram:

[![plaintext vs ciphertext notation](/assets/uploads/2017/02/sc2.png)](/assets/uploads/2017/02/sc2.png)

Now, let's take a totally random new block `X`. It's a block we create, that we control, that we can change, hit, eat. Take it together with the last ciphertext block of our example, `C_5`, and concatenate them.

We then have the following diagram:

[![concatenation notation](/assets/uploads/2017/02/sc3.png)](/assets/uploads/2017/02/sc3.png)

Using what we've seen before, we can write `P'2` as follows:

```
# Equality 1
P'2 = decrypt(C_5) ⊕ X
```

We also have the following formula for `C_5`:

```
# Equality 2
C_5 = encrypt(P_5 ⊕ C_4)
```

So by replacing `C_5` in equality **1** with its representation from equality **2** we get:

```
P'2 = decrypt(encrypt(P_5 ⊕ C_4)) ⊕ X

# Now, decrypting a ciphertext gives the original text, so

P'2 = P_5 ⊕ C_4 ⊕ X
```

Here we are with an equation that links 2 known elements with two unknowns:

**Known**

* `X`: The element we control, that we can change, hit, eat
* `C_4`: The second to last block of the ciphertext.

**Unknown**

* `P_5`: The last plaintext block of the string, what we are trying to find
* `P'2`: The plaintext block associated with the concatenation of `X` and `C_5`

This equation no longer contains any cryptography, only `XOR`. We removed the cryptographic aspect with only math.

To solve this equation that currently has two unknowns, we bring our knowledge of the padding oracle into play.

### Let's invoke the oracle

So we have the following equality thanks to our mathematical reasoning:

```
P'2 = P_5 ⊕ C_4 ⊕ X

# So

P_5 = P'2 ⊕ C_4 ⊕ X
```

This equality only contains the `XOR` operation. As you know, `XOR` is a bitwise operation, so we can split this equality by computing it byte by byte. Our blocks being 8 bytes, we have the following equations:

```
P_5[0] = P'2[0] ⊕ C_4[0] ⊕ X[0]
P_5[1] = P'2[1] ⊕ C_4[1] ⊕ X[1]
P_5[2] = P'2[2] ⊕ C_4[2] ⊕ X[2]
P_5[3] = P'2[3] ⊕ C_4[3] ⊕ X[3]
P_5[4] = P'2[4] ⊕ C_4[4] ⊕ X[4]
P_5[5] = P'2[5] ⊕ C_4[5] ⊕ X[5]
P_5[6] = P'2[6] ⊕ C_4[6] ⊕ X[6]
P_5[7] = P'2[7] ⊕ C_4[7] ⊕ X[7]
```

We also know that decrypting a ciphertext must give a plaintext with a valid padding, so ending with `0x01` or `0x02 0x02`, etc. Since we control all the bytes of `X`, we can brute-force the last byte until the decryption algorithm returns valid text. In this case, it will mean that the plaintext's padding is valid, so it ends with `0x01`.

_We don't take false positives into account in this article. Indeed, there is a (small) chance that the plaintext ends with `0x02 0x02` or other paddings, but these cases are rare. I may update the article to take them into account later._

Once we've found the byte that gives valid padding, so the `0x01` padding, by taking the equality only on the last byte (so at index 7, since our blocks are 8 bytes)...

```
P_5[7] = P'2[7] ⊕ C_4[7] ⊕ X[7]
```

... we can solve the equality since we know `P'2[7]` which is precisely `0x01`, but also `X[7]` which is the brute-force value and `C_4[7]` which is in the received ciphertext.

With all this information, we therefore find the last byte of the last plaintext block of the text (which is padding, but it's a good start)!

Now, to find the previous byte (so at index 6), we just need to choose `X[7]` such that `P'2[7] = 0x2` and then brute-force `X[6]` so that the padding is valid. When we have a value for `X[6]` that gives valid padding, that means we also have `P'2[6] = 0x2`, and so we can solve the equality:

```
P_5[6] = P'2[6] ⊕ C_4[6] ⊕ X[6]
```

since we have all the values in hand.

This reasoning must be repeated until we find all the plaintext values in the block.

Once the block is decrypted, just take the other blocks and apply exactly the same reasoning. This is how we find the blocks `P_4`, `P_3` and `P_2`.

A problem arises however to find the block `P_1`. Indeed, for the previous cases, we relied on knowing the ciphertext block preceding the block currently being decrypted. However, for the first block, we need to know the IV used. In this case, no miracle:

* Either you know the IV, in which case it's the same reasoning,
* Or you try to guess it using usual combinations, such as a null IV, or a sequence of consecutive bytes.

If ever you can't find it, then you'll have to settle for decrypting blocks 2 to N.

## Python script

Here is the Python script I wrote for AES128 CBC encryption:

```python
#/usr/bin/env python3

from Crypto.Cipher import AES
BLOCK_SIZE = 128
key = '0123456789abcdef'
IV = BLOCK_SIZE // 8 * '\x00'
mode = AES.MODE_CBC

"""
AES 128 CBC encryption
"""
def encipher(plain):
    encryptor = AES.new(key, mode, IV=IV)
    padded_plain = set_padding(plain)
    return encryptor.encrypt(padded_plain)


"""
AES 128 CBC decryption
Returns False if the padding is not valid
"""
def decipher(cipher):
    decryptor = AES.new(key, mode, IV=IV)
    plain_padded = decryptor.decrypt(cipher)
    if not is_padding_valid(plain_padded):
        return False
    return plain_padded

"""
Adds the padding based on the block size
"""
def set_padding(data, size_block=128):
    if size_block % 8 != 0:
        return False
    size_block_byte = size_block//8
    padding = size_block_byte - (len(data) % size_block_byte)
    data += chr(padding)*padding
    return data


"""
Removes the padding
"""
def del_padding(data):
    return data[:-data[-1]]


"""
Checks the validity of the padding
"""
def is_padding_valid(data):
    if len(data) == 0:
        return False
    c = data[-1]
    return data[-c:] == bytes([c])*c

"""
Splits a buffer into blocks based on the provided size
"""
def get_blocks(data, size_block=128):
    return [data[i*(128//8):(i+1)*(128//8)] for i in range(len(data)//(128//8))]

"""
Decrypts the message
If the IV is provided, the first block is also decrypted
"""
def decrypt(cipher, IV=None, block_size=128):
    cipher_blocks = get_blocks(cipher)
    res = b""
    if IV is not None:
        cipher_blocks = [bytes(IV, "utf-8")] + cipher_blocks

    # Blocks are decrypted one by one
    for _ in range(len(cipher_blocks)-1):
        plain = b""
        last_cipher_block = cipher_blocks[-1]
        trail = b""

        # For each block, we decrypt byte by byte
        for k in range(block_size//8):

            # Brute force to find the byte that gives the right padding
            for i in range(256):
                flip = bytes([i])
                cipher_block_attack = (15-k) * b'\x00' + flip + trail
                cipher_both_block =b"".join([cipher_block_attack, last_cipher_block])

                # We check the validity of the padding after decryption
                if decipher(cipher_both_block):
                    last_plain = (k+1) ^ cipher_blocks[-2][15-k] ^ i
                    plain = bytearray([last_plain]) + plain
                    trail = b""

                    # If the right padding is found, the controlled block (X in the article) is updated
                    for l in range(k+1):
                        last_byte = (k+2) ^ plain[-l-1] ^ cipher_blocks[-2][15-l]
                        trail = bytearray([last_byte]) + trail
                    break

        # Remove the decrypted block
        cipher_blocks = cipher_blocks[:-1]
        res = plain + res
        
    return del_padding(res)


plain = "This is the s3cret key boyz so let's go to work :D"
ciphered = encipher(plain)

print(decrypt(ciphered, IV))
```

When we run the program, we get the expected result:

```
$ python padding_oracle.py 
bytearray(b"This is the s3cret key boyz so let\'s go to work :D")
```

Peace love flex!
</content>
</invoke>