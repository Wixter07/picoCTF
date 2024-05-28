# mod1

So the challenge description is pretty self explanatory. We get a message that has a set of numbers. What we do now is `%37` with each number in the message and we have to map the remainder to the following character set: 0-25 is the alphabet (uppercase), 26-35 are the decimal digits, and 36 is an underscore. Wrote the following code to solve the problem and got the flag.![Screenshot (2)](https://github.com/Wixter07/CRYPTONITE-JTP-2/assets/150792650/efda7191-4599-425d-bc5a-18188c679e39)

The flag- `picoCTF{R0UND_N_R0UND_ADD17EC2}`

# miniRSA

Looks like we get a cipher text with bunch of random numbers which is encrypted using **RSA** algorithm and some instructions. The message could be decoded by writing a python solution script, but I choose to use an online decoder and specified Public Key Value as 3. The image below shows the result.![Screenshot (1)](https://github.com/Wixter07/CRYPTONITE-JTP-2/assets/150792650/ff93fa6e-f7f7-469a-9d75-23308a30138f)

The flag- `picoCTF{n33d_a_lArg3r_e_d0cd6eae}`

# Mod 36

The cipher is encrypted using ROT13. Pasted the `cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_jdJBFOXJ}` cipher text in CyberChef ROT13 decrypter to get the flag.

The flag- `picoCTF{next_time_I'll_try_2_rounds_of_rot13_wqWOSBKW}`

# The Numbers

 At a glance, we can know that the numbers in the text `16 9 3 15 3 20 6 {20 8 5 14 21 13 2 5 18 19 13 1 19 15 14}` are related to alphabets. The number 1-26 correspond to alphabets A-Z. With this, we can get the flag for the challenge.

 The flag- `PICOCTF{THENUMBERSMASON}`

 # 13

 Easy one. The cipher text is ROT13 encrypted so used CyberChef ROT13 decrypter to decrypt `cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}` to get the flag.
![Screenshot (42)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/f170879b-87f3-4bb6-a342-054d29cd185c)

The flag- `picoCTF{not_too_bad_of_a_problem}`

# Easy1

So it's a basic Vignere cipher text with the `UFJKXQZQUNB` as the cipher text and `SOLVECRYPTO` as the key. Used the Vignere decoder from CyberChef to get the flag.
![Screenshot (44)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/55bc75c1-4696-4827-bb6d-ea8899a74eaa)

The flag- `picoCTF{CRYPTOISFUN}`

# caeser

We get a cipher text ` picoCTF{gvswwmrkxlivyfmgsrhnrisegl}` and it seems that the flag part has been encrypted. Going by the challenge name, It's probably using caeser cipher. But I didn't get anything useful when I ran the cipher text on CyberChef caeser decrypter. So I tried a online multi decoder tool called [CacheSleuth](https://www.cachesleuth.com/multidecoder/) which gave out something useful as shown below.
![Screenshot (45)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/0a568fe2-ac2d-424c-b43a-702228c3ac81)

The flag- `picoCTF{crossingtherubicondjneoach}`

# Vignere

Pasted the Vignere cipher text `rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_f85729e7}` on CyberChef Vignere decoder to get the flag.

The flag- `picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_d85729g7}`

# rail-fence

As the instructions say, the cipher `Ta _7N6D8Dhlg:W3D_H3C31N__387ef sHR053F38N43DFD i33___N6` is encrypted using rail-fence with 4 rails. Pasted the cipher text on CyberChef rail-fence cipher decoder and set Key as 4 to get the flag.
![Screenshot (46)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/66facae0-9612-4467-8fc6-1eaea4dab385)

The flag- `picoCTF{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_83F6D8D7}`

# morse-code

We get a audio file `morse_chal.wav` which had morse audio. So used an online audio morse decoder tool and got this output for the audio file.
![Screenshot (47)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/06688feb-063b-41cd-8741-f7bc8dfebbdb)
After replacing the spaces with '_' , we get the flag.

The flag- `picoCTF{WH47_H47H_90D_W20U9H7}`

# credstuff

We get two files, a `usernames.txt` and `passwords.txt` file. As the instruction says that the first username corresponds to the first password, we need to find the serial number of the user `cultiris` to get his password. I opened both the text files on Notepad++ which shows the line numbers, I searched for `cultiris` and found the username in line number `378`. Then went to line number `378` on the `passwords.txt` file annd got this password ` cvpbPGS{P7e1S_54I35_71Z3}`. It's highly probable that the password is ROT13 encrypted so decoded it on CyberChef and got the flag.
![Screenshot (48)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/4abb0439-8e66-44e4-9ef1-2d3a6f6a89aa)

The flag- `picoCTF{C7r1F_54V35_71M3}`

# substitution0

So looking at the txt file, it looks jumbled at first and it's not smart to try any decoder on such a long text. Looking closely at `DECKFMYIQJRWTZPXGNABUSOLVH` and keeping mind the challenge name, It seems that the characters in `DECKFMYIQJRWTZPXGNABUSOLVH` corresponds to characters of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'. So looked for an online character substitution tool and luckily, found one on CyberChef. I tried replacing `DECKFMYIQJRWTZPXGNABUSOLVH` with 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' and the output started to look like it has something useful to offer. Since the text file had lower case characters too, I tried replacing `DECKFMYIQJRWTZPXGNABUSOLVHdeckfmyiqjrwtzpxgnabusolvh` with 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrtuvwxyz' and got the flag.
![Screenshot (49)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/66d88a0b-bedb-44d3-a146-cd759cf07cd1)

The flag- `picoCTF{5UB5717U710N_3V0LU710N_59533A2E}`

# substitution2

This text file was difficult to understand and there was no clues on how to replace the  characters with other ones. The only thing visible was the curly braces at the end of the text file that suggested that the flag was somewhere around there. So while I was looking for some automatic character substitution solving tools, I came across one automatic mono alphabet substitution tool on [DCODE](https://www.dcode.fr/monoalphabetic-substitution). I decided to try it out and thankfully, it gave out the flag where I expected it to.\
![Screenshot (51)](https://github.com/Wixter07/HARSHITH-JTP-2/assets/150792650/eee1eee0-1158-4799-b7c4-410cc0c5eb9f)


The flag- `PICOCTF{N6R4M_4N41Y515_15_73D10U5_42EA1770}`


 # New Caeser

 This one was a bit difficult for me to undestand at first but I did understand the first half of the python code given. To understand the rest half of the `b16_encode` function, I referred to this writeup by [vivian dai](https://vivian-dai.github.io/PicoCTF2021-Writeup/Cryptography/New%20Caesar/New%20Caesar.html).
 Wrote the code below with some help from the writeup.

 **import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

cipher_text = "kjlijdliljhdjdhfkfkhhjkkhhkihlhnhghekfhmhjhkhfhekfkkkjkghghjhlhghmhhhfkikfkfhm"

def b16_decode(solve):
    dec = ""
    for idx in range(0, len(solve), 2):
    
        c1 = solve[idx]
        c2 = solve[idx + 1]
        
        c1 = ALPHABET.index(c1)
        c2 = ALPHABET.index(c2)
        
        binary1 = "{0:04b}".format(c1)
        binary2 = "{0:04b}".format(c2)
        
        binary = int(binary1 + binary2, 2)

        dec += chr(binary)
    return dec

def unshift(c, k):
   
    t1 = ord(c) + LOWERCASE_OFFSET
    t2 = ord(k) + LOWERCASE_OFFSET
    
    return ALPHABET[(t1 - t2) % len(ALPHABET)]

def is_ascii(s):
    return len(s) == len(s.encode())
for letter in ALPHABET:
    
    dec = ""
    
    for i, c in enumerate(cipher_text):
        dec += unshift(c, letter)
    
    dec = b16_decode(dec)

    if is_ascii(dec) and " " not in dec:
        print("Flag: picoCTF{%s}" % dec)**

       

 The flag- `picoCTF{et_tu?_1ac5f3d7920a85610afeb2572831daa8}`



# Mind your Ps and Qs

Easy, just paste the values in a RSA decrypter without specifying P and Q values as:- 

**c: 964354128913912393938480857590969826308054462950561875638492039363373779803642185
n: 1584586296183412107468474423529992275940096154074798537916936609523894209759157543
e: 65537**

![Screenshot (20)](https://github.com/Wixter07/picoCTF/assets/150792650/3ccb51d2-90d7-4ed7-aa8c-7ee450c3cd43)


The flag - `picoCTF{sma11_N_n0_g0od_73918962}`



# substitution1

The text file contained the message and as suggested by the challenge name, we do character substitution to decrypt the message. I could've tried solving this by doing a frequency attack by replacing the most occuring character with "E" and so  on, but I resorted to an automatic monoalphabetic substitution decoder. It gave me the flag as **PICOCTF{FR3ZU3NCY_4774CK5_4R3_C001_6E0659FB}**. I replaced the **Z** in Frequency with **Q** and solved the challenge.

![Screenshot (23)](https://github.com/Wixter07/picoCTF/assets/150792650/ebd392cb-9392-4824-bde3-0d601e52c65c)

The flag - `PICOCTF{FR3QU3NCY_4774CK5_4R3_C001_6E0659FB}`

# Hide to See

So used steghide on the image and gave nothing as passphrase. This extracted an **encrypted.txt** file. Read it to get this.

![Screenshot (29)](https://github.com/Wixter07/picoCTF/assets/150792650/dd389e15-b4a4-4bf4-a298-34de82065360)

Used an Atbash decrypter to get the flag

![image](https://github.com/Wixter07/picoCTF/assets/150792650/4e342f07-3b95-4643-829d-e1527e18a63a)

The flag - `picoCTF{atbash_crack_1f84d779}`

# ReadMyCert

So this is a Certificate Signing Request file. I could've tried running openssl to get the flag but I used this CSR Decoder from [sslshopper](https://www.sslshopper.com/csr-decoder.html) and pasted the text in the CSR file to get the flag.

![image](https://github.com/Wixter07/picoCTF/assets/150792650/4a88edca-59d3-4135-90e7-71c4f364bfcb)

The flag - `picoCTF{read_mycert_a7163be8}`

# rotation

Got an encrypted.txt file which had flag like text. Going by the name, the positions are probably rotated so used this multi decoder from [CacheSleuth](https://www.cachesleuth.com/multidecoder/). It has an auto ROT solver, and we got the flag at ROT8

![image](https://github.com/Wixter07/picoCTF/assets/150792650/b6737fc9-77fa-4b41-8739-4c740b2fdb3c)

The flag - `picoCTF{r0tat1on_d3crypt3d_25d7c61b}`

# la cifra de

So we have with us a long text which we got from the netcat connection. Boxentriq cipher identifier didnt give anything but multi decoder from [CacheSleuth](https://www.cachesleuth.com/multidecoder/) gave me the answer in Vigenere. So from the Vigenere decipher we got this

`It is interesting how in history people often receive credit for things they did not create`

`During the course of history, the Vigenère Cipher has been reinvented many times`

`It was falsely attributed to Blaise de Vigenère as it was originally described in 1553 by Giovan Battista Bellaso in his book La cifra del. Sig. Giovan Battista Bellaso`

`For the implementation of this cipher a table is formed by sliding the lower half of an ordinary alphabet for an apparently random number of places with respect to the upper halfpicoCTF{b311a50_0r_v1gn3r3_c1ph3r6fe60eaa}`

`The first well-documented description of a polyalphabetic cipher however, was made around 1467 by Leon Battista Alberti.
The Vigenère Cipher is therefore sometimes called the Alberti Disc or Alberti Cipher.`

`In 1508, Johannes Trithemius invented the so-called tabula recta (a matrix of shifted alphabets) that would later be a critical component of the Vigenère Cipher`

`Bellaso’s second booklet appeared in 1555 as a continuation of the first. The lower halves of the alphabets are now shifted regularly, but the alphabets and the index letters are mixed by means of a mnemonic key phrase, which can be different with each correspondent.`

The flag - `picoCTF{b311a50_0r_v1gn3r3_c1ph3r6fe60eaa}`

# tapping

Connected using netcat to get the morse code. Translated it using an online tool to get the flag.

![image](https://github.com/Wixter07/picoCTF/assets/150792650/a071e526-c3a4-46bc-a653-0e081d6d5145)

The flag - `PICOCTF{M0RS3C0D31SFUN1261438181}`

# Flags

We get a image file with Navy Signal Flags. Used this tool from [dcode](https://www.dcode.fr/maritime-signals-code) and gave the flag inputs to get the flag.

![image](https://github.com/Wixter07/picoCTF/assets/150792650/b3735d43-cbf0-419d-9321-8c1faace0032)

The flag - `PICOCTF{F1AG5AND5TUFF}`

# Mr. Worldwide

This one was a bit of a hassle. The message.txt file had latitudes and longitudes of loations. I assumed that we need the first letter of this place, but first letter of what? The city or the country name?. So I ploted a table with the first letters of both the city and the country to see which one is useful. And I got the flag from the first letters of the cities using Google Maps.

`35.028309, 135.753082 - Kyoto - **K**`

`46.469391, 30.740883 - Odesa - **O**`

`39.758949, -84.191605 - Dayton - **D**`

`41.015137, 28.979530 - Istanbul - **I**`

`24.466667, 54.366669 - Abu Dhabi - **A**`

`3.140853, 101.693207 - Kuala Lumpur - **K**`

`9.005401, 38.763611 - Addis Ababa - **A**`

`-3.989038, -79.203560 - Loja - **L**`

`52.377956, 4.897070 - Amsterdam - **A**`

`41.085651, -73.858467 - Sleepy Hollow - **S**`

`57.790001, -152.407227 - Kodiak - **K**`

`31.205753, 29.924526 - Al Azaritah - **A**`

Kodiak is a place in Alaska

The flag - `picoCTF{KODIAK_ALASKA}`

# waves over lambda

The challenge description said that it used a lot of substitutions to encrypt the message. So I pasted the cipher in the automatic Monoalphabetic Substitution Tool from [dcode](https://www.dcode.fr/monoalphabetic-substitution) to get the flag.

![image](https://github.com/Wixter07/picoCTF/assets/150792650/5023fd38-9bf1-4903-898b-5e6659f22e80)


The flag - `FREQUENCY_IS_C_OVER_LAMBDA_AGFLCGTYUE`

# Daschund Attacks

Connected to the netcat to get the n,c,e values for decrypting the RSA. The hint was small d values. I searched what happens when d values are small, that's when I came to learn about [Weiner's Attack](https://en.wikipedia.org/wiki/Wiener%27s_attack). Though I didn't understand much, I just pasted the values is RSA Decrypted from dcode and luckily I got to see this in the results

![image](https://github.com/Wixter07/picoCTF/assets/150792650/17c8c239-cc92-4b03-be21-fbe657905f61)

It computed p,q using n,e values and d computed with p,q,e values. Then it decrypted using c,d,n values.

The flag - `picoCTF{proving_wiener_6907362}
`

# transposition trial

So the we get the message and it seems to have some sort of transposition of character on the flag. Divided the message into chunks of three and moved the third character to the first position in every chunk.

The message - **`heT\fl \g a\s i\icp\CTo\{7F\4NR\P05\1N5\_16\_35\P3X\51N\3_V\091\B0A\E}2\`**
The decrypted message after transposition - **`The flag is picoCTF{7R4N5P051N6_15_3XP3N51V3_109AB02E}`**

The flag - `picoCTF{7R4N5P051N6_15_3XP3N51V3_109AB02E}`

# b00tl3gRSA2

So the challenge description mentioned 

**In RSA d is a lot bigger than e, why don't we use d to encrypt instead of e?**

So I connected using netcat to get the n,c,e values. I opened RSA decrypter tool from dcode and gave the n and c inputs but swapped the e and n inputs. I gave the e value obtained from the connection in d and gave the general e value **65537** in e and got the flag.

The flag - `picoCTF{bad_1d3a5_2152720}`

# No Padding, No Problem

Just a CPA attack
Look through it [CPA on RSA](https://crypto.stackexchange.com/questions/2323/how-does-a-chosen-plaintext-attack-on-rsa-work)

The flag - `picoCTF{m4yb3_Th0se_m3s54g3s_4r3_difurrent_4005534}`

# rsa_oracle

Same thing as above, just do a CPA on the oracle

# pixelated

Overlay the images and the resulting image shows the flag

The flag - `picoCTF{2a4d45c7}`

# spelling quiz

So the source code we can infer that the flag.txt and study-guide.txt file both have been encrypted with a substitution cipher using a random key.

Giving the contents of both the files to [dcode](https://www.dcode.fr/monoalphabetic-substitution) and it will give the flag 


The flag - `picoCTF{PERHAPS_THE_DOG_JUMPED_OVER_WAS_JUST_TIRED}`



# basic-mod2

Pretty straight forward

The flag - `picoCTF{1NV3R53LY_H4RD_DADAACAA}`
