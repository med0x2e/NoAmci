### TLDR:
A PoC for using DInvoke to patch AMSI.dll in order to bypass AMSI detections triggered when loading .NET tradecraft via Assembly.Load().
.Net tradecraft can be compressed, encoded (encrypted if required) in order to keep the assembly size less than 1MB, then embedded as a resource
 to be loaded after patching amsi.dll memory.

### Testing Notes:
* Make sure that both the default Class and Main method have the 'public' access modifier before compressing/encoding your assembly (Ghostpack ..etc).
* favicon.ico corresponds to a encoded and compressed version of safetykatz using DeflateStream and GzipStream APIs,
  this helped reducing the size of assemblies then embedded as resources in order to be able to use them with execute-assembly
* Helper.cs have methods which can be used to compress other .Net binaries (Ghostpack ..etc).
* Source code for DInvoke was copied from SharpSploit PR submitted by @FuzzySecurity and @TheWover. (all doc comments removed)
* Tested via cobalt strike execute-assemby on Windows Build 1908/1903 and against a common EDR product (after removing all comments) -> no detections were triggered.

### TODO:
* Assemblies can be encrypted and hosted on a remote endpoint, then loaded and injected into memory (NET-Assembly-Inject-Remote for a PoC) 
this would decouple NoAmci from Assemblies and allow to dynamically load an assembly of 
choice at runtime while keeping NoAmci.exe size less small.


### Disclaimer:
should be used for authorized red teaming and/or nonprofit educational purposes only. 
Any misuse of this software will not be the responsibility of the author. 
Use it at your own networks and/or with the network owner's permission.

