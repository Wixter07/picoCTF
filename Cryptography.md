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


```
import string

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
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2) % len(ALPHABET)]

def is_ascii(s):
    return len(s) == len(s.encode())

for letter in ALPHABET:
    dec = ""
    for i, c in enumerate(cipher_text):
        dec += unshift(c, letter)
    dec = b16_decode(dec)
    if is_ascii(dec) and " " not in dec:
        print("Flag: picoCTF{%s}" % dec)
```
    



       

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

The flag - `picoCTF{su((3ss_(r@ck1ng_r3@_60f50766}`

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

# Play Nice

The nc gives the ciphertext and the grid. It's a playfair cipher so used this tool from [dcode](https://www.dcode.fr/playfair-cipher). Just remember to change the grid to 6*6 so that it takes the grid characters in.

The flag - `3f4b60ebf36369258d8638d2038c7ad1`

# triple-secure

The message is encrypted thrice. calculate p,q,r values using factordb and the code below should get the flag.

```
from Crypto.Util.number import long_to_bytes , inverse

n1 = 15192492059814175574941055248891268822162533520576381643453916855435310880285336743521199057138647926712835561752909538944229702432795423884081992987060760867003375755338557996965825324749221386675061886921763747311599846248565297387814717840084998677273427776535730840343260681623323972936404815862969684384733188827100528542007213405382537935243645704237369770300643318878176739181891072725262069278646319502747718264711249767568106460533935904219027313131270918072460753061248221785076571054217566164086518459844527639082962818865640864990672033657423448004651989761933295878220596871163544315057550871764431562609
n2 = 15896482259608901559307142941940447232781986632502572991096358742354276347180855512281737388865155342941898447990281534875563129451327818848218781669275420292448483501384399236235069545630630803245125324540747189305877026874280373084005881976783826855683894679886076284892158862128016644725623200756074647449586448311069649515124968073653962156220351541159266665209363921681260367806445996085898841723209546021525012849575330252109081102034217511126192041193752164593519033112893785698509908066978411804133407757110693612926897693360335062446358344787945536573595254027237186626524339635916646549827668224103778645691
n3 = 16866741024290909515057727275216398505732182398866918550484373905882517578053919415558082579015872872951000794941027637288054371559194213756955947899010737036612882434425333227722062177363502202508368233645194979635011153509966453453939567651558628538264913958577698775210185802686516291658717434986786180150155217870273053289491069438118831268852205061142773994943387097417127660301519478434586738321776681183207796708047183864564628638795241493797850819727510884955449295504241048877759144706319821139891894102191791380663609673212846473456961724455481378829090944739778647230176360232323776623751623188480059886131
e = 65537
c = 5527557130549486626868355638343164556636640645975070563878791684872084568660950949839392805902757480207470630636669246237037694811318758082850684387745430679902248681495009593699928689084754915870981630249821819243308794164014262751330197659053593094226287631278905866187610594268602850237495796773397013150811502709453828013939726304717253858072813654392558403246468440154864433527550991691477685788311857169847773031859714215539719699781912119479668386111728900692806809163838659848295346731226661208367992168348253106720454566346143578242135426677554444162371330348888185625323879290902076363791018691228620744490
p = 119660120407416342093521198875970200503652030026184999838840951544471188235057764512149622436334754517070092115889922087976143409261665862157884453930404483415351610238154321433871054239568905273137919725917526056473901359312949883646592913381637999260828599289383860301717085920912559762712295164989106012643
q = 126963703597214242111055793388455179890379067770512076858587717197146928847759121114335398860091528260297687323794942479532566444647858389461128295471609299505781851499310733099158304584543771415239918097328230929655601250453281393102266829307661217314893414986784482323832179578849867366834284687012845412763
r = 132846951895793538897077555403967847542050766700952197146228251113081712319440889155149846202888542648969351063239105740434095718011829001684551658508591803707420131965877374781379009502046474415909376904718002094203010990824838428607725944298259738507797326637681632441750845743202171364832477389321609195337
phi1 = (p-1)*(q-1)
phi2 = (p-1)*(r-1)
phi3 = (q-1)*(r-1)
d1 = inverse(e,phi1)
d2 = inverse(e,phi2)
d3 = inverse(e,phi3)
m3 = pow(c,d3,n3)
m2 = pow(m3,d2,n2)
m1 = pow(m2,d1,n1)
print(long_to_bytes(m1))

```

The flag - `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}`

# rsa-pop-quiz

Calculations based on basic RSA formulas. The last calculation for the plaintext should give the flag.

The flag - `picoCTF{wA8_th4t$_ill3aGal..ode01e4bb}`

# sum-o-primes

So we get **n** nad **x** where x is defined as **x=p+q**. A z3 script should solve this easily if the constraints are set properly to get p and q. Then it's just plain old decryption since we have ciphertext value too. 

```
from z3 import *
from Crypto.Util.number import inverse , long_to_bytes

def hex_to_int(hex_str):
    return int(hex_str, 16)

def solve(x_hex, n_hex):
    x = hex_to_int(x_hex)
    n = hex_to_int(n_hex)

    p = Int('p')
    q = Int('q')

    solver = Solver()

    solver.add(p + q == x)
    solver.add(p * q == n)

    if solver.check() == sat:
        model = solver.model()
        p_val = model[p].as_long()
        q_val = model[q].as_long()
        return p_val, q_val
    else:
        return None, None

x_hex = "152a1447b61d023bebab7b1f8bc9d934c2d4b0c8ef7e211dbbcf841136d030e3c829f222cec318f6f624eb529b54bcda848f65574896d70cd6c3460d0c9064cd66e826578c2035ab63da67d069fa302227a9012422d2402f8f0d4495ef66104ebd774f341aa62f493184301debf910ab3d1e72e357a99c460370254f3dfccd9ae"
n_hex = "6fc1b2be753e8f480c8b7576f77d3063906a6a024fe954d7fd01545e8f5b6becc24d70e9a5bc034a4c00e61f8a6176feb7d35fe39c8c03617ea4552840d93aa09469716913b58df677c785cd7633d1b7d31e2222cab53be235aa412ac5c5b07b500cf3fd5d6b91e2ddc51bff1e6eec2cb68723af668df36e10e332a9cbb7f3e2df9593fa0e553ed58afec2aa3bc4ae8ef1140e4779f61bdeae4c0b46136294cf151622e83c3d71b97c815b542208baa28207225f134c5a4feac998aeb178a5552f08643717819c10e8b5ec7715696c3bf4434fbea8e8a516dfd90046a999e24a0fb10d27291eb29ef3f285149c20189e7d0190417991094948180196543b8c91"
p, q = solve(x_hex, n_hex)
print("p =", (p))
print("q =", (q))

c = 2862537339040469147429657894344199928557031834390107583219729603518151458232752655435765178741847862681985518014369908230465656681188452816388220057841477741951807370846472046013718654924186479831297315008200827303965506316115312185032136602875438400387736740902196374239905780326853099910635897462206320968355042526152404835351422548524752308082386282793614300087991456840160462341088790668081742054292524665828459909511307682427456625705560299547231552417332610842874439163798240180613567066151575717456490027272337259628798278336279800627826934011806508731399100283618512809664315701708126217489999299504239618063
e = 65537
n = 14107968002788601163232271919683185628377930258855714024361251700443482916159477972019175057249307805020558833578002642814353244251935462643122106832841875886751834868578847553067993029534859873400111872030760141512265217100084094768240561746973517000260205166788073707007901559501857058570047904411103289205303895005723927634856272992046301957255183083869294681094092965797803167854696071500371486827898745037887826839037430790364261755123274123835361705705618196178336329858713462923973567226715396383555224515182961278023099436837662748725809380387313268345922304316857780150905037767522499166165808213903858699409
phi = (p-1)*(q-1)
d = inverse(e,phi)
m = pow(c,d,n)
print(long_to_bytes(m))
```

The flag - `picoCTF{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_3921def5}`

# interencdec

Base64 decrypt **YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6ZzJhMnd6TW1zeWZRPT0nCg==** to get **b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzg2a2wzMmsyfQ=='** 
Base64 decrypt **d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzg2a2wzMmsyfQ==** to get **wpjvJAM{jhlzhy_k3jy9wa3k_86kl32k2}**
Then ROT7 OF **wpjvJAM{jhlzhy_k3jy9wa3k_86kl32k2}** to get the flag

The flag - `picoCTF{caesar_d3cr9pt3d_86de32d2}`

# C3

The flag - `picoCTF{adlibs}`

# Custom encryption

The flag - `picoCTF{custom_d2cr0pt6d_66778b34}`

