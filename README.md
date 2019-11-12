# daniel-ness/ansible-vault

[![Build Status](https://travis-ci.org/daniel-ness/ansible-vault.svg?branch=master)](https://travis-ci.org/daniel-ness/ansible-vault)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/100a16f06c0a41b78eab8d5cb1d9d69d)](https://www.codacy.com/manual/daniel-ness/ansible-vault?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=daniel-ness/ansible-vault&amp;utm_campaign=Badge_Grade)

## Overview
I've no idea if anyone else will ever possibly require this, but I did.

This package allows you to decrypt `ansible-vault` encrypted strings back to 
plaintext. 

Initially I was using `shell_exec` to pipe the output of these commands into
my application, but that seemed ugly so instead I've ported the logic from
https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/vault/__init__.py.

## Installation
```$php
composer require daniel-ness/vault-ansible 
```

## Usage

```$php
<?php

use DanielNess\Ansible\Vault\Decrypter;

$vaultText = '$ANSIBLE_VAULT;1.1;AES256
  38353635623865383037653936623235306331616630633732366331613438313135646535623962
  6366616234316663626161653361373936303731393736300a626639653939373635623138396463
  66613665666538376634326136323032303132383335303933336330666331633339616133333633
  6534653436663231620a336162353438306163313463303237363265313763326266346465656335
  39346438303334376534663130336466326162643266623630303233656430613330';

$plainText = Decrypter::decryptString($vaultText, $password);
echo $plainText . "\n";

> itCanDecryptOnePointOneString
```

## Todo
- Encryption

## License
MIT License

Copyright (c) 2019 Daniel Ness

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.