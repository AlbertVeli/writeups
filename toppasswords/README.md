# Howto generate lists of top passwords

Sometimes it is useful to have a short list of common passwords. For instance
if the password format is slow or if it is used to brute force logins.

It is easy enough to find lists online of the worst 100 passwords or
worst 1000. But what if you want to generate a list of you own?
Here is one way to do it. In the example below we will compile a list of
the top 10.000 Have I Been Pwned passwords.

[@troyhunt](https://github.com/troyhunt) has made this possible by
publishing hashed passwords ordered by prevalence (ordered by count).
These are combined passwords from all the leaks available at his
site Have I Been Pwned.

## Get the [hibp list of hashes](https://haveibeenpwned.com/Passwords)

Choose either SHA-1 or NTLM, *ordered by prevalence*. Be kind to Troy
and use the torrent if possible.

## Select top 10.000

The unpacked file is huge. Say we want the top 10.000 passwords, then we only
need the first 10.000 lines.
```bash
head -10000 pwned-passwords-ordered-by-count.txt > top10k.txt
```

Each line contains additional information (password count). Here are the top 10.
```
7C4A8D09CA3762AF61E59520943DC26494F8941B:22390492
F7C3BC1D808E04732ADF679965CCC34CA7AE3441:7481454
B1B3773A05C0ED0176787A4F1574FF0075F7521E:3752262
5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3533661
3D4F2BF07DC1BE38B20CD6E46949A1071F9D0E3D:3006809
7C222FB2927D828AF22F592134E8932480637C0D:2840404
6367C48DD193D56EA7B0BAAD25B19455E529F5EE:2803614
20EABE5D64B0E216796E834F52D61FD0B70332FC:2425568
E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D:2391888
8CB2237D0679CA88DB6464EAC60DA96345513964:2308872
```

But we only want the part up to the colon character.
```bash
cat top10k.txt | cut -d: -f 1 > top10k.sha1
```

You might also want to lowercase the hashhex (more common).
Add tr to the cmdline pipe above if you want to do that.
```bash
... | tr '[:upper:]' '[:lower:]'
```

## Compile a good wordlist

Head over to [hashes.org](hashes.org), select *lists* from the menu. Search for
*Leak 'Have I been Pwned V2'* and click on *Plain*, it's on the line Cracked.
Then do the same for *Leak 'Have I been Pwned V3 (V2 excluded)'*.
You may also want to consider a donation to hashes.org because of all the
hard work they have put into creating it and keeping it up to date.

## (optional) merge the wordlists
If you want you can merge the two lists into one even bigger list.
I use the program *unique* from the
[John the Ripper](https://github.com/magnumripper/JohnTheRipper)
suite for this purpose.
```bash
cat 515_have-i-been-pwned-v2_found.txt 899_have-i-been-pwned-v3--v2-excluded-_found.txt | unique hibp_hashesorg.txt
```

## Crack with john
The main binary in the John the Ripper suite is just called john.

Line below cracks the hashes in top10k.sha1 using the big wordlist.
If you didn't merge the wordlists, then just run the line below
twice, once for each wordlist (wordlist is specified with -w).
```
john -format:Raw-SHA1 -pot:hibp.pot -w:hibp_hashesorg.txt top10k.sha1
```

The argument -pot tells john where to keep information about the cracked
passwords (the potfile). It is a good habit to use separate potfiles
for each task. But the passwords are not in order in the potfile.
To show them in order, use --show.

## Show top passwords in order of prevalence.
```
john -pot:hibp.pot --show top10k.sha1
?:123456
?:123456789
?:qwerty
?:password
?:111111
?:12345678
?:abc123
?:1234567
?:password1
?:12345
...
```

If you want to remove the questionmark and print the line number instead, add
```
| sed 's/^?://' | awk '{print NR, $0}'
```
to the --show command.

## Crack with hashcat
Very similar to john. Mode 100 is sha1. See all modes with hashcat --help.
```
hashcat -m 100 --potfile-path hc.pot top10k.sha1 hibp_hashesorg.txt
```

Side note. My hashcat version (compiled from source, git commit from
2019-01-02) seems to have a bug with -m 100. It only cracked about
70% of the passwords. I had to add -O to the cmdline to crack all
passwords, strange. -O uses a different, optimized, version of the
algorithm that limits the password length to 32 characters.

## Recrack
Like john, hashcat also has a --show option, but it shows the hashes and
passwords in "sorted hash" order.
We want to show them in the order they appear in top10k.sha1. The easiest
solution is to "recrack" the hashes hashcat found with john and then use
john --show, as before, to show the passwords in the correct order.

The format of the lines in hashcat.pot is
```
0bf782fd7c9ca8d71788502041f4f154209ab002:starlight
```
So we want the second column using : as separator.
```
cat hc.pot | cut -d: -f2- > tmp.txt
john -format:Raw-SHA1 -pot:hibp.pot -w:tmp.txt top10k.sha1
john -pot:hibp.pot --show top10k.sha1
?:123456
?:123456789
?:qwerty
?:password
...
?:anthony13
?:6543211
?:ghbywtccf

9988 password hashes cracked, 12 left
```

As you see there are still 12 uncracked among the top 10.000 passwords.
You can try to crack them yourself using rules, masks and what not. If you
manage to crack any new ones consider
[uploading](https://hashes.org/upload.php) the new founds to hashes.org
and it will be included in the next update.

Good Luck!
