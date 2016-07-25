HabboEncryption
==========

For the latest Habbo version use the HabboEncryption class.
To initialize the HabboEncryption class, put this in your main class somewhere

```
  // Load your rsa keys (D, Modules and Exponent).
  RSACParameters rsaParameters = RSACParameters.FromXmlFile(@"D:\path\to\your\rsa.keys");
  
  HabboEncryption.GetInstance(rsaParameters, 128); // returns a new static instance of the encryption handler with 128bits diffiehellman keys.
  // or
  HabboEncryption habboEncryption = new HabboEncryption(rsaParameters, 128); // creates a new instance of the encryption handler with 128bits diffiehellman keys.
```

For the initialization for the crypto event is the packet: string, string

```
  response.WriteString(HabboEncryption.GetInstance().GetRSADiffieHellmanPKey());
  response.WriteString(HabboEncryption.GetInstance().GetRSADiffieHellmanGKey());
```

And for the last message event which you get after sending the initialization packet is

```
  string cipherPublicKey = request.ReadString();
  BigInteger sharedKey = HabboEncryption.GetInstance().CalculateDiffieHellmanSharedKey(cipherPublicKey);
  if (sharedKey != 0)
  {
    ARC4 rc4 = HabboEncryption.InitializeARC4(sharedKey);
  }
  else
  {
    // throw a error
  }
  
  // Initialize a new response
  response.WriteString(HabboEncryption.GetInstance().GetRSADiffieHellmanPublicKey());
```

When not using the static method, change up ``HabboEncryption.GetInstance()`` to your variable instance.

NOTE: C# BigInteger class uses and returns LittleEndian byte array!