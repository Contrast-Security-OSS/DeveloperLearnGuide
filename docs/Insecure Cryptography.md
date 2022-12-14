---
layout: default
title: Insecure Cryptography
nav_order: 5
---

# Insecure Cryptography
{: .no_toc }

{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---
[CodeSec: Find this vulnerability straight from your CLI](https://www.contrastsecurity.com/developer/codesec/){: .btn .btn-primary .fs-4 .mb-4 .mb-md-0 .mr-2 }

## Insecure Authentication Protocol
<br/>
The use of outdated and insecure authentication protocols puts your application and sensitive data at serious risk.

### Overview 
<br/>

- **Basic Authentication** 
<br/> 
This protocol simply hides the plaintext username and password inside of Base64 encoding, and issues it as an Authorization header. To any attacker sniffing network traffic, the credentials may as well be in plaintext. 
<br/> 
Base64 offers zero cryptographic functionality. It is a keyless, deterministic algorithm, and most attack tools decode such credentials automatically.

- **Digest Authentication** 
<br/> 
This protocol is superior to Basic Authentication in that it doesn't offer a user's password in plaintext. Instead, it offers a method of authentication that proves knowledge of a secret (a password) without passing the password directly. 
<br/>  
Since RFC2617, the optional security features of Digest Authentication have been improved, but not enforced. The disadvantages of the protocol, including the changes in RFC2617, are subtle. 
<br/> 
Digest authentication is also easily attacked in a man-in-the-middle (MITM) scenario. Use of digest authentication precludes the usage of recommended password digests like bcrypt.
Passwords, or some digested combination of the password and other metadata must be available to the server in plaintext in order to use this protocol.

### How To Fix 
<br/>
Moving authentication protocols is not easy. That being said, there are serious, fundamental weaknesses in the 
protocols chosen. The best, long term recommendation is to move towards a form-based authentication. 

It is extremely unlikely that specification-driven HTTP authentication protocols will ever meet the security 
requirements of your organization. It's also unlikely that improvements to these protocols will be integrated into 
browsers and server frameworks in any reasonable amount of time. 


## Insecure Encryption Algorithms

### Overview 
<br/>
We use these these types of algorithms in order to transform data into an encrytped state, with the goal of facilitating secure communication. 
Not all are made equal, in terms of both complexity and ability to protect data. 

Many, still in use, have degraded over time, and are no longer suitable for use.
Let's take a look at some unsafe examples using a DES cipher:  
<br/> 
Switching encryption algorithms in the code is very easy; data migration is a much bigger problem. 
Here's code that uses a DES cipher, which is considered **very weak** by today's standards because of its small key size of 56 bits: 

### Java  
<br/>

**Unsafe Example** 

```java
final Cipher weakCipher = Cipher.getInstance("DES"); // Unsafe!
```

**Safe Example** 

The following code uses an AES cipher, which is considered much stronger for many reasons, including a key length of at least 128 bits: 


```java
final Cipher strongCipher = Cipher.getInstance("AES/CTR/NoPadding"); // Safer!
```


### .NET/.NET Core
<br/>

**Unsafe Example** 

```csharp
// C#:
DESCryptoServiceProvider weakCipher = new DESCryptoServiceProvider();    // Unsafe!
``` 

**Safe Example** 

The following code uses an AES cipher, which is considered much stronger for many reasons, including a key length of at least 128 bits: 

```csharp
// C#:
Aes strongCipher = Aes.Create();    // Safer!
```

### VB.NET 
<br/>

**Unsafe Example** 

```vb
Dim weakCipher As New DESCryptoServiceProvider()    ' Unsafe!
``` 

**Safe Example**  

The following code uses an AES cipher, which is considered much stronger for many reasons, including a key length of at least 128 bits:  


```vb
Dim strongCipher As Aes = Aes.Create()    ' Safer!
``` 

### Node 
<br/>

**Unsafe Example** 

```js
var cipher = crypto.createCipher('DES'); // Unsafe!
``` 

**Safe Example** 

The following code uses an AES cipher, which is considered much stronger for many reasons, including a key length of at least 128 bits:  

```js
var cipher = crypto.createCipher('AES'); // Safer!
``` 


### Ruby 
<br/>

**Unsafe Example** 

```ruby
cipher = crypto.createCipher('des') // Unsafe!
``` 

**Safe Example** 

The following code uses an AES cipher, which is considered much stronger for many reasons, including a key length of at least 128 bits:  

```ruby
cipher = OpenSSL::Cipher::AES.new(128, :CTR) // Safer!
``` 


### Python  
<br/>

**Unsafe Example** 

```python
cipher = Crypto.Cipher.DES.new(key)
``` 

**Safe Example** 

The following code uses an AES cipher, which is considered much stronger for many reasons, including a key length of at least 128 bits:  

```python
cipher = Crypto.Cipher.AES.new(key, mode=Crypto.Cipher.AES.MODE_CTR)
``` 

## Summary 
<br/>

Although in the past, ECB (electronic codebook) and CBC (cipher block chaining) modes were popular, they both exhibit weaknesses that can be practically exploited. This is why our snippet utilizes the `CTR/NoPadding` mode and transformation. 
<br/><br/> 
CTR (Counter) mode turns AES into a stream cipher, making the encrypted traffic much more difficult to attack. This allows the code to resist Padding Oracle attacks, which have been used to break numerous systems, including Java Server Faces (JSF), ASP.NET/IIS, and Ruby on Rails.
<br/><br/> 
You should also always use integrity checking with HMACs, if possible. HMACs usually involve signing the hash of the encrypted blob with the private part of an asymmetric keypair. Without this protection, the code may also be vulnerable to bit flipping and other attacks that result from not guaranteeing the sender generated the ciphertext. Using an HMAC allows you to safely use CBC mode as well.  



## Insecure Hash Algorithms 

### Overview 
<br/>

There are lots of times when a hashing algorithm like MD5 or SHA-1 is used in a way that _doesn't_ represent realistic
risk to your organization. However, if you find yourself needing to switch hashing algorithms, doing it in the code is
very easy; data migration is a much bigger problem. 
<br/>  

Below are code examples that uses a MD5 digester, which is considered **broken** by today's standards because it's not nearly as collision-resistant as
once thought: 

### Java 
<br/>

**Unsafe Example** 

```java
MessageDigest badDigester = MessageDigest.getInstance("MD5"); // Unsafe
``` 

**Safe Example**  

The following code retrieves a SHA-2 cipher, which is considered **much** stronger for many reasons (including a 256-bit hash, which is less likely to fall victim to a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack):

```java
MessageDigest safeDigester = MessageDigest.getInstance("SHA-256"); // Safe!
``` 

### .NET/.NET Core 
<br/>

**Unsafe Example** 

```csharp
// C#:
MD5 badDigester = MD5.Create();  // Unsafe!
``` 

- Safe  

The following code retrieves a SHA-2 cipher, which is considered **much** stronger for many reasons (including a 256-bit hash, which is less likely to fall victim to a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack): 

```csharp
// C#:
SHA256 safeDigester = SHA256Managed.Create();  // Safe!
``` 


### VB.NET 
<br/>

**Unsafe Example** 

```vb
Dim badDigester As MD5 = MD5.Create()  ' Unsafe!
``` 

**Safe Example** 

The following code retrieves a SHA-2 cipher, which is considered **much** stronger for many reasons (including a 256-bit hash, which is less likely to fall victim to a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack):  

```vb
Dim safeDigester As SHA256 = SHA256Managed.Create()  ' Safe!
``` 


### Node  
<br/>

**Unsafe Example** 

```js
var unsafeHash = crypto.createHash('md5'); // Unsafe!
``` 

**Safe Example**  

The following code retrieves a SHA-2 cipher, which is considered **much** stronger for many reasons (including a 256-bit hash, which is less likely to fall victim to a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack):  

```js
var saferHash = crypto.createHash('sha256'); // Safe!
``` 

### Ruby  
<br/> 

**Unsafe Example**  

```ruby
unsafeHash = Digest::MD5.digest('some string value') # Unsafe!
``` 

**Safe Example**  

The following code retrieves a SHA-2 cipher, which is considered **much** stronger for many reasons (including a 256-bit hash, which is less likely to fall victim to a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack):  

```ruby
saferHash = Digest::SHA256.digest('some string value') # Safe!
``` 

### Python  
<br/> 

**Unsafe Example** 

```python
unsafeHash = Crypto.Hash.MD5.new(b'value to hash') # Unsafe!
```

**Safe Example**  

The following code retrieves a SHA-2 cipher, which is considered **much** stronger for many reasons (including a 256-bit hash, which is less likely to fall victim to a [birthday attack](https://en.wikipedia.org/wiki/Birthday_attack):  

```python
saferHash = Crypto.Hash.SHA256.new(b'value to hash') # Safe!
``` 

## Summary  
<br/> 

Attacks against unsafe digests are more than theoretical; undirected collisions can be found on an average laptop in a few
seconds. Directed collisions can be generated with relatively modest resources. That being said, all practical attacks would seem
to require cryptographers of rare quality and the resources of a mid-large sized organization.  
<br/> 
Therefore, you should carefully decide how likely you are to face such an attack when estimating the severity of this issue.

## Weak Number Generation  
<br/>

It's hard to tell what purpose that the PRNG is used for, but if it's being used to generate secrets, like authentication tokens, remember me codes, or temporary passwords, its contents may be guessable. 

### Java 
<br/>

Weak PRNGs like [Random](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/random/package-summary.html){{#link}} have a relatively small amount of predetermined, random numbers to draw from. An attacker can usually gather lots of samples and determine where in the set of numbers their data comes from, and start predicting what the next secrets generated by the application will be. 


Switching from an insecure pseudo-random number uuidGen (PRNG) to a secure one is easy. Usually, `unsafe` random numbers are generated one of two ways: 

```java
Random r = new Random();
int num = r.nextInt(); // insecure!

... or ...

double d = Math.random(); // insecure!
``` 

Substituting [SecureRandom](https://docs.oracle.com/javase/6/docs/api/index.html)instead of `Random` makes the first way `safe`: 

```java
SecureRandom r = SecureRandom.getInstance("SHA1PRNG");
r.nextBytes(new byte[4]); // ask the SHA1PRNG to seed safely - only needed once per creation
int num = r.nextInt(); // secure!
``` 

Unfortunately there is no direct, secure substitution for `Math.random()`. You can get a securely random `double` with similar code:

```java
SecureRandom r = SecureRandom.getInstance("SHA1PRNG");
r.nextBytes(new byte[4]); // ask the SHA1PRNG to seed safely - only needed once per creation
double d = r.nextDouble();
``` 

**Please Note:** These are some common pitfalls when using `SecureRandom`:
- Hardcoding your seed. 
<br/> 
This makes your numbers the same every time your application runs - not very secure at all.

- Forgetting to seed.
<br/> 

By default, the `SecureRandom` doesn't seed the PRNG output. This means your output will be the same every time. 
To safely seed the output, call `SecureRandom.nextBytes()` as soon as you create the instance, or call the `SecureRandom.setSeed(long)` function with real entropy.

- Overusing secure entropy sources.
<br/> 

Using `SecureRandom` more than you have to can lead to performance problems as the calling threads end up blocking as they wait for more entropy to become available from the system.



### .NET/.NET Core 
<br/>

Weak PRNGs like .NET's `Math.Random` have a relatively small amount of predetermined, random numbers to draw from. An attacker can usually gather lots of samples and determine where in the set of numbers their data comes from, and start predicting what the next secrets generated by the application will be.

Switching from an insecure pseudo-random number uuidGen (PRNG) to a secure one is easy. Usually, `unsafe` random numbers are generated one of two ways:

```csharp
// C#:
Random r = new Random();
int num = r.Next;          // Insecure! While trying to get a random number from 0 to Int32.MaxValue
double d = r.NextDouble * UInt64.MaxValue;   // Insecure! While trying to get a random number from 0 to UInt64.MaxValue
``` 

In .NET, the `Random.Next` function returns a number between 0 and Int32.MaxValue and `Random.NextDouble` returns a floating point number between 0.0 and 1.0.  So we multiply the Double value to produce a range similar to what Next() provides. 

Substituting `RandomNumberGenerator` instead of `Random` makes the random number generation safe:

```csharp
// C#:
RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
byte[] int_bytes = new byte[4];
rng.GetBytes(int_bytes); // Get the random bytes
int num = Math.Abs((int)BitConverter.ToInt32(int_bytes,0)); // Convert them to an int
// ToInt32 can return a negative int, so we get the absolute value

byte[] double_bytes = new byte[8];
rng.GetBytes(double_bytes);
double d = (double) BitConverter.ToUInt64(double_bytes,0); // Convert them to a double
// ToUInt64 cannot return a negative double so we don't need to bother getting the absolute value
```

### Node 
<br/>

Weak PRNGs like javascript's `Math.random` have a relatively small amount of predetermined, random numbers to draw from. An attacker can usually gather lots of samples and determine where in the set of numbers their data comes from, and start predicting what the next secrets generated by the application will be. 


Switching from an insecure pseudo-random number uuidGen (PRNG) to a secure one is easy. Usually, `unsafe` random numbers are generated like so: 

```js
function random(floor, ceiling) {
    return Math.random() * (ceiling - floor) + floor;
}
``` 

The `Math.random` function returns a number between 0 and 1, so we multiply the floating point value to scale the number to a desired range. However, while the number appears to be random, it is not. In order to increase the variance in output, the random uuidGen is seeded from the current time. 


`crypto.randomBytes` should be substituted for `Math.random`. This function uses your system's Entropy to yield random values which are considered cryptographically `safe`: 

```js
var crypto = require('crypto');
var random = crypto.createRandom(10); // array of values between 0 and 255, e.g: [80 32 f0 a4 25 e3 88 e6 6c b2]
``` 

Care must be taken when encoding these values to your desired character set so that the length of your character set does not bias the distribution of characters in your output. 


### Ruby 
<br/>  

Weak PRNGs like [Random](https://ruby-doc.org/core-2.1.3/Random.html) have a relatively small amount of predetermined, random numbers to draw from. An attacker can usually gather lots of samples and determine where in the set of numbers their data comes from, and start predicting what the next secrets generated by the application will be.


Switching from an insecure pseudo-random number to a secure one is easy. Usually, unsafe random numbers are generated like so:

```ruby
	Random.rand(integer)
``` 

The `Random.rand` function returns a number between 0 and the given integer. However, while the number appears to be random, it is not. On first call, Random uses a seed value that can be determined. 

`SecureRandom.random_bytes` should be substituted for `Random.rand` for any instance in which cryptography is required. This function uses `OpenSSL::Random` to yield random values which are considered cryptographically safe: 

```ruby
	SecureRandom.random_bytes # array of bytes x00 - xff; default length being 16
``` 

Care must be taken when encoding these values to your desired character set so that the length of your character set does not bias the distribution of characters in your output.

### Python 
<br/>  

Weak PRNGs like [random.random()](https://docs.python.org/3/library/random.html#random.random) have a relatively small amount of predetermined, random numbers to draw from. An attacker can usually gather lots of samples and determine where in the set of numbers their data comes from, and start predicting what the next secrets generated by the application will be. 


Switching from an insecure pseudo-random number generator to a secure one
is easy. Usually, unsafe random numbers are generated like so: 

```python
import random
result = random.randint(a, b)
``` 

The `random.randint` function returns a number in the
range between a and b (inclusive). However, while the number appears to be random, it
is not. On first call, `random.randint` uses a seed value that can be
determined. 

`secrets.randbits` should be substituted for
`random.randint` for any instance in which cryptography is required.
This function uses the most secure random generator available on your platform to yield
random bit streams which are considered cryptographically safe: 

```python
import secrets
result = secrets.randbits(num_bits)
``` 

Care must be taken when encoding these values to your desired character
set so that the length of your character set does not bias the distribution of
characters in your output.


