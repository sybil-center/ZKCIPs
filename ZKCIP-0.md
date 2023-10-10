# **Zero Knowledge Credentials v0.1 (status: Draft)**

> ## **Preface**

The provided information represents an early version of the protocol that contains the concepts and main ideas. However, it should be noted that the majority of these ideas will undergo further refinement and development to form the final version of the protocol.

The key words *MAY*, *MUST*, *MUST NOT*, *RECOMMENDED*, and *SHOULD* in this document are to be interpreted as described in [BCP 14](https://datatracker.ietf.org/doc/html/bcp14) [[RFC2119](https://www.w3.org/TR/vc-data-model/#bib-rfc2119)] [[RFC8174](https://www.w3.org/TR/vc-data-model/#bib-rfc8174)] when, and only when, they appear in all capitals, as shown here.

> ## **Introduction**

Zero Knowledge Credentials (zkCredentials) - a protocol for subject authentication without disclosing any information about the subject.

The protocol contains information about the structure of the credential - zkCredential Data Model (hereinafter referred to as zkCredential) and the process of transforming this data structure into a format supported by modern protocols (zkSNARK, zkSTARK) and implementations of Zero Knowledge Proofs (ZKPs) such as Mina - Snarkyjs, Circom, Noir, etc. The transformation process is necessary to create the required ZKP from zkCredential to provide this ZKP to the verifier (the party that needs to authenticate the subject).

The process of transforming zkCredential into a format that can be used together with the ZKP creation function, as input data, is the most important and critical part of the protocol. This process defines all the constraints that must be imposed on the format of zkCredential.

> ## **Objectives**

This protocol is necessary to provide the subject with the ability to confirm their attributes in the digital space without disclosing the attributes themselves. This allows the subject to avoid leaving a digital trace of their identity in the digital space and gives them complete control over their representation in the digital world.

Furthermore, in ideological terms, this protocol brings us closer to a future where the concept of sovereign identity ([https://github.com/WebOfTrustInfo/self-sovereign-identity/blob/master/self-sovereign-identity-principles.md](https://github.com/WebOfTrustInfo/self-sovereign-identity/blob/master/self-sovereign-identity-principles.md)) makes more sense than the current state of affairs with the Verifiable Credential Data Model by W3C (hereinafter referred to as the VC specification).

Another important goal of this protocol is to create a digital environment where the subject can use digital credentials to confirm their attributes wherever possible – in a centralized application, smart contract, zk application, etc. This is another crucial issue that the VC specification is unable to address.

> ## ZK Credential: Data structure

ZK Credential MUST be described by the data structure presented below.

```typescript
type ZKCredential = {
  isr: {
    id: { t: number, k: string }
  }
  sch: number; 
  isd: number;
  exd: number; // 0 if expiration date is undefined
  sbj: {
    id: { t: number, k: string }
  } & Record<string, any>
  proof: Proof[]
}
```

Shorter field names within the provided data structure contribute to reducing the number of constraints during the creation of Zero-Knowledge Proofs (ZKPs).

> ## **ZK Credential: Explanation of the Data Structure**

Having the initial form of zkCredential, let's discuss the significance of this form.

`Identifiers` - fields with the key `"id"` and the value **MUST** be an object with two fields: `"t"` for the identifier type – a number and `"k"` for the public key in Base58 encoding format. The `"t"` field indicates which cryptographic signing algorithm the key `"k"` belongs to. For example, `id.t = 1` indicates that `id.k = "bs…8"` is a public key of Ed25519. This intentional structure of identifiers allows for the extension of zkCredential identifiers to support other types of public keys, such as keccak256 (which is not well-suited for ZKP) or new algorithms that perform faster than Ed25519 for ZKPs.

`Issuer` - `"isr"` indicates who issued the zkCredential. `"isr"` object MUST has the `"id"` field as `Identifier`, and other fields **MUST NOT** be present.

`Schema` - `"sch"` defines the structure of the object contained within the "sbj" object. The "sch" field is a number.

`Issuance Date` - `"isd"` represents the date of issuing the zkCredential. The value of the `"isd"` field is a number that determines the time in UNIX format.

`Expiration Date` - `"exd"` represents the date after which the zkCredential becomes invalid. The value of the `"exd"` field is a number that determines the time in UNIX format. If zkCredential has no expiration date, the value of this field should be set to 0.

`Subject` - `"sbj"` contains attributes possessed by the subject. `"sbj"` object **MUST** has `"id"` field as Identifier field, and other fields MUST align with the `"sch"` field. Values of fields inside `"sbj"` can be `strings`, `booleans`, `numbers`, `objects`, `lists` with FIXED lengths. Subject fields **MUST NOT** be optional, meaning all fields within the `"sch"` field and in internal object fields are required.

`Proof` - `"proof"` at this stage of the zkCredentials protocol is a list containing cryptographic proof that zkCredential is issued by a specific issuer. It also includes public information necessary to verify this proof, such as a public key and zkCredential transformation schema suitable for signing and ZKP creation functions (further details below). The structure of the proof is described below.

> ## **ZK Credential: Limitations**

To make zkCredential compatible with ZKP, several limitations had to be introduced:

1. zkCredential **MUST NOT** have optional fields. All fields must be defined or have default values.
2. The size of any objects inside zkCredential **MUST** be fixed. If an object within zkCredential has three properties, it means it has exactly three properties, no more and no less.
3. The size of lists **MUST** be fixed. If zkCredential contains a list, its size must be fixed.

These three points describe all the limitations that must be considered when creating and issuing zkCredential.

It is worth noting that the "proof" property does not have such limitations.

This set of limitations is justified because the ZKP creation function takes a fixed list of values as input.

> ## **ZK Credential: Preparation**

To make zkCredential suitable for the ZKP creation function, it needs to undergo a process called `preparation`. It is essential to note that the "proof" property does not participate in the preparation and signing process.

The preparation process consists of three stages:

1. ### Normalization

The zkCredential sorts its objects in a specific order. The order of values in the normalized zkCredential is as follows:

1. `isr`: The issuer, where the `id` object should have the fields `k` and `t` in that order.
2. `sch`: The schema.
3. `isd`: The issuance date.
4. `exd`: The expiration date.
5. `sbj`: An object containing the subject's attributes. The first field inside the `sbj` object should be the "id" object, where the first field has the key "k" and the second field has the key `t`. The remaining fields of the `sbj` object should be sorted in ascending order of their keys. The same principle applies to nested objects, except for lists, where the order of elements should remain unchanged during normalization.

Below is the code describing the normalization function.

```typescript
function normalize<T extends ZKCredential>(credential: T): T {
  const target: Record<string, any> = {};
  target.isr = {
    id: {
      k: credential.isr.id.k
      t: credential.isr.id.t,
    }
  };
  target.sch = credential.sch;
  target.isd = credential.isd;
  target.exd = credential.exd;
  const subjectProps = Object.keys(credential.sbj)
    .filter((key) => key !== "id")
    .reduce((subjectProps, prop) => {
      subjectProps[prop] = credential.sbj[prop];
      return subjectProps;
    }, {} as Record<string, any>);
  target.sbj = {
    id: {
      k: credential.subject.id.k,
      t: credential.subject.id.t
    },
    ...sortKeys(subjectProps, { deep: true })
  };
  return target as T;
}
```

It's important to note that the `normalize` function uses the `sortKeys` function to sort fields inside objects in ascending order of their keys, along with their nested objects, except for lists, where the order of elements is preserved.

2. ### Transformation

The conversion of all object values into a format suitable for Zero-Knowledge Proofs (ZKPs) according to the `transformation schema`. A more detailed process of transforming object values is described in the `Transformation Schema` section.

3. ### Get Value List

From the normalized and transformed zkCredential, a list of values is obtained, including values from nested objects, following the order set during normalization.

Below is the code describing the function to get the values list.

```typescript
function getValues(obj: any, vector?: any[]) {
  if (!vector) vector = [];
  if (!Array.isArray(obj)) {
    obj = Object.values(obj);
  }
  obj.forEach((value: any) => {
    if (typeof value === "object" && value !== null) {
      getValues(value, vector);
    } else if (typeof value !== "undefined") {
      vector?.push(value);
    }
  });
  return vector;
}
```

> ## **Signing the prepared zkCredential**

After the zkCredential has been prepared, it goes through a signing process. The prepared zkCredential is transformed into a list of bytes or digits. This list of bytes or digits is then used as input to a hash function, such as Poseidon or Pedersen, to generate a hash value. Finally, the hash value is signed using a signature algorithm, such as Ed25519 or Baby JubJub. The resulting digital signature serves as proof of the authenticity and integrity of the zkCredential during verification processes.

> ## Verification of the prepared zkCredential

Verification of the prepared zkCredential should take place directly within the ZKP creation function. For this reason, the ZKP creation function should take the following inputs: the public key, which is used to verify the signature, the signature itself, and the prepared zkCredential as a list of transformed values.

Inside the ZKP creation function, it is possible to verify that the prepared fields of the zkCredential correspond to the expected ones. After this validation, the verification process can proceed as follows: the hash is computed from the prepared zkCredential (list of bytes or digits), and then the signature is verified. The verification function takes the public key, signature, and hash as inputs.

By performing these verification steps, the integrity and authenticity of the zkCredential can be ensured during the ZKP creation process

> ## Transformation Graph

### Base Terms

The transformation graph is a structured set of rules that govern the modification and transformation of one type of value into another type of value. It consists of two significant components:

1. Graph nodes (types): The transformation graph nodes represent different types and are interconnected through transformation or modification functions. Each type in the graph can be converted or modified to another type using specific functions. For example, a string of type "utf8" can be transformed into a "bytes" type using the "utf8-bytes" transformation function. All base types are represented in the base types table - Table 1.
2. Graph links (functions): The links in the graph are functions that enable the transition from one type to another. Each function in the graph contains an input type, representing the type before the transformation or modification, and an output type, representing the type after the transformation or modification. All functions are documented in the base functions table - Table 2. There are three types of functions within the graph.

a. Transformation functions: These functions transform one type into another type.

b. Modification functions: These functions modify the value of a type, such as a hash function.

c. Mix functions: These functions combine both transformation and modification functionalities.

> NOTE: If type name and function name are equals it means that function does not transform or modify type of value

General representation of the Transformation graph shown in figure below.

![TransformationGraph.png](https://res.craft.do/user/full/89efce61-9b1d-0ff5-4eda-03346cd124c3/doc/daa894df-07f2-4185-baf0-759075935e53/11e4dcb2-117b-4dac-974e-4ec804a6795f)

Figure 1 – General representation of the Transformation graph

### Extensibility

Developers have the option to expand the base transformation graph by introducing their own types and functions. To do so, the new types or functions must adhere to the specified format: ":". For each new type or function, comprehensive implementation documentation must be provided.

Type documentation should include the following details:

- Name of the type
- Description containing implementation specifics

Function documentation should include the following details:

- Name of the function
- Input type
- Output type
- Description containing implementation specifics

Here are a couple of examples illustrating the format:

- " mina:field"- identifier is " mina ", and the type name is "field".
- "mina:uint128-field" – identifier is "mina", and the function name is "uint128-field".

### Appendix

Table 1 – Base transformation graph types

| Name      | Description                                                                                     |
| --------- | ----------------------------------------------------------------------------------------------- |
| utf8      | UTF-8 encoded string, according to https://datatracker.ietf.org/doc/html/rfc3629                |
| base64    | Base64 encoded string, according to https://datatracker.ietf.org/doc/html/rfc3629               |
| base32    | Base32 encoded string, according to https://datatracker.ietf.org/doc/html/rfc3629               |
| base16    | Base16 encoded string, according to https://datatracker.ietf.org/doc/html/rfc3629               |
| base64url | Base64url encoded string, according to https://datatracker.ietf.org/doc/html/rfc7515#appendix-C |
| base58    | Base58 encoded string, according to https://en.bitcoin.it/wiki/Base58Check_encoding             |
| ascii     | ACSII encoded string, according to https://datatracker.ietf.org/doc/html/rfc20                  |
| int16     | Integer 16 bits size                                                                            |
| int32     | Integer 32 bits size                                                                            |
| int64     | Integer 64 bits size                                                                            |
| int128    | Integer 128 bits size                                                                           |
| int256    | Integer 256 bits size                                                                           |
| uint16    | Unsigned integer 16 bits size                                                                   |
| uint32    | Unsigned integer 32 bits size                                                                   |
| uint64    | Unsigned integer 64 bits size                                                                   |
| uint128   | Unsigned integer 128 bits size                                                                  |
| uint256   | Unsigned integer 256 bits size                                                                  |
| float32   | Float according to IEEE 754                                                                     |
| boolean   | Boolean                                                                                         |
| bytes     | bytes array                                                                                     |

Table 2 – Base transformation graph functions

| Name                                                                            | Description                                                                                                                                                                                                             | Input type name                                                           | Output type name                                                          |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| bytes-‘x’, where ‘x’= {utf8, base64, base32, base16, base64url, base58, ascii}  | Transform bytes to encoded ‘x’ string, where x = {utf8, base64, base32, base16, base64url, base58, ascii}                                                                                                               | bytes                                                                     | ’x’, where ‘x’ = {utf8, base64, base32, base16, base64url, base58, acsii} |
| ‘x’-bytes, where ‘x’ = {utf8, base64, base32, base16, base64url, base58, ascii} | Transform encoded ‘x’ string to bytes, where ‘x’ = {utf8, base64, base32, base16, base64url, base58, ascii}                                                                                                             | ’x’, where ‘x’ = {utf8, base64, base32, base16, base64url, base58, ascii} | bytes                                                                     |
| bytes-int’x’, where x = {16, 32, 64, 128, 256}                                  | Transform bytes to int’x’, where ‘x’ = {16, 32, 64, 128, 256}. Bytes order is big-endian.                                                                                                                               | bytes                                                                     | int’x’, where ‘x’ = {16, 32, 64, 128, 256}.                               |
| int’x’-bytes, where x = {16, 32, 64, 128, 256}.                                 | Transform int’x’ to bytes, where ‘x’ = {16, 32, 64, 128, 256}. Bytes order is big-endian                                                                                                                                | int’x’, where ‘x’ = {16, 32, 64, 128, 256}.                               | bytes                                                                     |
| bytes-uint’x’, where x = {16, 32, 64, 128, 256}.                                | Transform bytes to uint’x’, where ‘x’ = {16, 32, 64, 128, 256}. Bytes order is big-endian.                                                                                                                              | bytes                                                                     | uint’x’, where ‘x’ = {16, 32, 64, 128, 256}.                              |
| uint’x’-bytes, where x = {16, 32, 64, 128, 256}.                                | Transform uint’x’ to bytes, where ‘x’ = {16, 32, 64, 128, 256}. Bytes order is big-endian                                                                                                                               | uint’x’, where ‘x’ = {16, 32, 64, 128, 256}.                              | bytes                                                                     |
| bytes-float’x’, where x = {32}.                                                 | Transform bytes to float’x’, where ‘x’ = {32}, according to IEEE 754.                                                                                                                                                   | bytes                                                                     | float’x’, where ‘x’ = {32}                                                |
| float’x’-bytes, where x = {32}                                                  | Transform float’x’, where ‘x’ = {32}, according to IEEE 754                                                                                                                                                             | float’x’, where ‘x’ = {32}                                                | bytes                                                                     |
| ‘x’-boolean, where ‘x’ = {utf8, acsii}                                          | Transform encoded ‘x’ string (“true”, “false”) to boolean, where ‘x’ = {utf8, acsii}. If string = “true” transformers to boolean = true, if string = “flase” transformers to boolean = false, otherwise throw exception | {utf8, acsii}                                                             | boolean                                                                   |
| boolean-‘x’, where ‘x’ = {utf8, acsii}                                          | Transform boolean to encoded ‘x’ string, where ‘x’ = {utf8, acsii}. If boolean = true transforms to string = “true”, if boolean = false transforms to string = “false”                                                  | boolean                                                                   | string.’x’, where ‘x’ = {utf8, acsii}                                     |
| int’x’-boolean, where x = {16, 32, 64, 128, 256}                                | Transform int’x’, where ‘x’ = {16, 32, 64, 128, 256} to boolean. If int = 1 then boolean = true, if int = 0 then boolean = false, otherwise throw error                                                                 | int’x’, where ‘x’ = {16, 32, 64, 128, 256}                                | boolean                                                                   |
| boolean-int’x’, where x = {16, 32, 64, 128, 256}                                | Transform boolean to int’x’, where ‘x’ = {16, 32, 64, 128, 256}. If boolean = true then int = 1, if boolean = false then int = 0                                                                                        | boolean                                                                   | int’x’, where ‘x’ = {16, 32, 64, 128, 256}                                |
| ‘x’-int’y’, where ‘x’ = {utf8, acsii}; ‘y’ = {16, 32, 64, 128, 256}             | Transform string ‘x’ encoded to int’y’ where ‘x’ = {utf8, acsii}; y = {16, 32, 64, 128, 256}. E.g. If string = “17” then int = 17                                                                                       | {utf8, acsii}                                                             | int’y’, where ‘y’ = {16, 32, 64, 128, 256}                                |
| int’y’-‘x’, where ‘x’ = {utf8, acsii}; ‘y’ = {16, 32, 64, 128, 256}             | Transform int’y’ to encoded ‘x’ string, where ‘x’ = {utf8, acsii}; y = {16, 32, 64, 128, 256}. E.g. If int = 17 then string = “17”                                                                                      | int’y’, where ‘y’ = {16, 32, 64, 128, 256}                                | {utf8, acsii}                                                             |
| ‘x’-uint’y’, where ‘x’ = {utf8, acsii}; ‘y’ = {16, 32, 64, 128, 256}            | Transform string ‘x’ encoded to uint’y’ where ‘x’ = {utf8, acsii}; y = {16, 32, 64, 128, 256}. E.g. If string = “17” then uint = 17                                                                                     | {utf8, acsii}                                                             | uint’y’, where ‘y’ = {16, 32, 64, 128, 256}                               |
| uint’y’-‘x’, where ‘x’ = {utf8, acsii}; ‘y’ = {16, 32, 64, 128, 256}            | Transform uint’y’ to encoded ‘x’ string, where ‘x’ = {utf8, acsii}; ‘y’ = {16, 32, 64, 128, 256}. E.g. If int = 17 then string = “17”                                                                                   | uint’y’, where ‘y’ = {16, 32, 64, 128, 256}                               | {utf8, acsii}                                                             |
| ‘x’-float’y’, where ‘x’ = {utf8, acsii}; ‘y’ = {32}                             | Transform string ‘x’ encoded to uint’y’ where ‘x’ = {utf8, acsii}; ‘y’ = {32}. E.g. If string = “17.1” then float = 17.1                                                                                                | {utf8, acsii}                                                             | float’y’, where ‘y’ = {32}                                                |
| float’y’-‘x’, where ‘x’ = {utf8, acsii}; ‘y’ = {32}                             | Transform float’y’ to encoded ‘x’ string, where ‘x’ = {utf8, acsii}; ‘y’ = {32}. E.g. If int = 17.1 then string = “17.1”                                                                                                | float’y’, where ‘y’ = {32}                                                | {utf8, acsii}                                                             |
| utf8                                                                            | No transformation or modification                                                                                                                                                                                       | utf8                                                                      | utf8                                                                      |
| base64                                                                          | No transformation or modification                                                                                                                                                                                       | base64                                                                    | base64                                                                    |
| base32                                                                          | No transformation or modification                                                                                                                                                                                       | base32                                                                    | base32                                                                    |
| base16                                                                          | No transformation or modification                                                                                                                                                                                       | base16                                                                    | base16                                                                    |
| base64url                                                                       | No transformation or modification                                                                                                                                                                                       | base64url                                                                 | base64url                                                                 |
| base58                                                                          | No transformation or modification                                                                                                                                                                                       | base58                                                                    | base58                                                                    |
| acsii                                                                           | No transformation or modification                                                                                                                                                                                       | acsii                                                                     | acsii                                                                     |
| int16                                                                           | No transformation or modification                                                                                                                                                                                       | int16                                                                     | int16                                                                     |
| int32                                                                           | No transformation or modification                                                                                                                                                                                       | int32                                                                     | int32                                                                     |
| int64                                                                           | No transformation or modification                                                                                                                                                                                       | int64                                                                     | int64                                                                     |
| int128                                                                          | No transformation or modification                                                                                                                                                                                       | int128                                                                    | int128                                                                    |
| int256                                                                          | No transformation or modification                                                                                                                                                                                       | int256                                                                    | int256                                                                    |
| uint16                                                                          | No transformation or modification                                                                                                                                                                                       | uint16                                                                    | uint16                                                                    |
| uint32                                                                          | No transformation or modification                                                                                                                                                                                       | uint32                                                                    | uint32                                                                    |
| uint64                                                                          | No transformation or modification                                                                                                                                                                                       | uint64                                                                    | uint64                                                                    |
| uint128                                                                         | No transformation or modification                                                                                                                                                                                       | uint128                                                                   | uint128                                                                   |
| uint256                                                                         | No transformation or modification                                                                                                                                                                                       | uint256                                                                   | uint256                                                                   |
| float32                                                                         | No transformation or modification                                                                                                                                                                                       | float32                                                                   | float32                                                                   |
| boolean                                                                         | No transformation or modification                                                                                                                                                                                       | boolean                                                                   | boolean                                                                   |
| bytes                                                                           | No transformation or modification                                                                                                                                                                                       | bytes                                                                     | bytes                                                                     |

> ## Transformation schema

The transformation schema is an object that contains information on how to properly transform the field values of the zkCredential according to Transformation graph. Here’s an example of a transformation schema.

```typescript
const transformSchema = {
  isr: {
    id: {
      k: [“base58-bytes”],
      t: [“uint64-bytes”]
    },
  },
  sch: [“uint128”],
  isd: [“uint128”],
  exd: [“uint128”],
  sbj: {
    id: {
      k: [“base58-bytes”],
      t: [“uint64-bytes”]
    },
    twitter: {
      id: [“uint128-bytes”],
      username: [“utf8-bytes”, “mina:poseidon”]
    }
  }
}
```

As observed in the transformation schema, it shares similarities with the zkCredential object itself. The key distinction is that the final values are represented as lists of strings, which are function names in the transformation graph. These function names indicate the input type and the transformed or modified output type (refer to the base transformation graph function table). To transform zkCredential according to the transformation schema, you must match the field names and execute operations on each field value based on the transformation graph.

For example, let's assume the value of field `zkCredential.sbj.twitter.username` is `"zk-credential"`, and the value of `transformationSchema.sbj.twitter.username` is `["utf8-bytes", "mina:poseidon"]`. To transform `sbj.twitter.username` to the correct form for the ZKP (Zero-Knowledge Proof) function, you need to:

1. Transform the value `"zk-credential"` to bytes according to the transformation graph function `"utf8-bytes"`.
2. Modify the result of the `"utf8-bytes"` function according to the function `"mina:poseidon"`
3. The resulting hashed bytes sequence becomes the transformation result for the field `zkCredential.sbj.twitter.username`.

In summary, the transformation process involves applying a series of functions from the transformation graph to the values of zkCredential fields, as specified in the transformation schema, to obtain the final transformed values for ZKP functions.

> NOTE: If zkCredential subject contains list as field value, then transformation schema value for the list property has to contains transformation graph function name list for each element of zcCredential subject list.

Example.

```typescript
const credential = {
  issuer: {
    id: {
      publickey: isrPubKey.toBase58(),
      type: 1,
    }
  },
  schema: 2,
  issuanceDate: new Date().getTime(),
  expirationDate: new Date().getTime() + 1000,
  subject: {
    id: {
      type: 1,
      publickey: sbjPubKey.toBase58()
    },
    possessions: [ // note: list size always 4
      "car",
      "house",
      "phone",
      "", // default element value
    ]
  },
};
```

For the zkCredential above, transformation schema will be:

```typescript
const transformSchema = {
  isr: {
    id: {
      k: ["base58-byte"],
      t: ["uint64-bytes"],
    },
  },
  sch: ["uint128"],
  isd: ["uint128"],
  exd: ["uint128"],
  sbj: {
    id: {
      k: ["base58-bytes"],
      t: ["uint64-bytes"]
    },
    possessions: [ // list size always 4
      ["utf8-bytes"],
      ["utf8-bytes"],
      ["acsii-bytes"],
      ["acsii-bytes", "mina:poseidon"]
    ]
  }
};
```

> ## **Proof**

A proof is an object that contains the necessary information for verifying the zkCredential. Its fields are as follows:

1. Public Key - "key": The public key of the issuer who signed the prepared hash of the zkCredential in base58 encoding.
2. Type - "type": Indicates the type of signature, for example, "Poseidon-BabyJubJub " - indicating that the prepared fields of the zkCredential are hashed using the "Poseidon" algorithm and then signed using Baby Jubjub elliptic curve.
3. Transform Schema - "transformSchema": An object that specifies how the fields of the zkCredential should be transformed during preparation. It should be represented as a base64url-encoded string obtained from a JSON object.
4. Signature - "sign": The signature created by the issuer according to the rules described in this protocol.
5. Target - "target": An auxiliary field that helps determine which blockchain is best suited to use this proof.

Example of a proof object:

```typescript
const proof = {
  key: "ac...1",
  type: "Poseidon:BabyJubJub ",
  target: "mina"
  transformSchema: "xq13.._123",
  sign: "saf...dsf"
}
```

The ZkCredential may contain multiple proofs in the form of a list, as shown below:

```typescript
const ZKCredential = {
  isr: {
    id: { t: 1, k: "ac...1" }
  },
  sch: 1, 
  isd: 1690474327,
  exd: 0, // 0 if expiration date is undefined
  sbj: {
    id: { t: 1, k: "vk...3" }
  },
  proof: [
    {
      key: "ac...1",
      type: "Poseidon-BabyJubJub",
      target: "mina"
      transformSchema: "xq13.._123",
      sign: "saf...dsf"
    },
    {
      key: "ac...1",
      type: "Poseidon-BabyJubJub ",
      target: "eip155"
      transformSchema: "ac33.._321",
      sign: "bas...ddf"
    }
  ]
}
```

> ## Compatibility with DID

The identifier property `id` in zkCredential is compatible with generative DID methods. For example, the `identifier` `id` with fields `t = 1` (i.e. Ed25519 or BabyJubJub) and `k = 24…9n` can be transformed into a DID using the following format: `did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:24…9n`.

> ## Compatibility with Verifiable Credential Data Model:

Verifiable Credentials (VCs) can be transformed into zkCredentials, but they need to be converted accordingly:

1. The `@context` field should be removed.
2. The first element of the `type` field, `VerifiableCredential`, should be removed. If there are multiple elements left in the `type` field after removing `VerifiableCredential`, then `n` new zkCredentials should be created, where `n` is the number of remaining elements in the `type` field. These new zkCredentials should correspond to the types or schemas. Next, the types of VCs should be converted to numerical equivalents, for example, `Person = 1`, `Pet = 2`, etc. After all the transformations, the `type` field should be renamed to `sch`.
3. Any identifier that appears in the VC should be converted into an identifier of zkCredential with fields "k" and "t". For example, if `VC.issuer.id = "did:key:123...567"`, it should be transformed into `id = { k: 123...345, t: 1 }`. It's worth noting that such transformation is possible only with algorithmic DID methods, and not all of them support this.
4. The values of the `issuanceDate` and `expirationDate` fields should be converted to UNIX format and represented as numbers. The field names should be converted to `isd` and `exd`.
5. The value of the `issuer` field, if it is a string in the format of a DID method as an identifier, should be transformed into the format of a zkCredential identifier, and the field name should be converted to `isr`. If the value of the `issuer` field is an object, then the `id` field inside this object, whose value is a DID string, should be converted into a zkCredential identifier, and the other fields of the `issuer` object should be discarded. The field name `issuer` should be renamed to `isr`.
6. The value of the `subject` field should be an object that contains the `id` field, with a value as a DID. The subject's identifier should be transformed into a zkCredential identifier. Other fields can remain unchanged. The field name `subject` should be converted to `sbj`.

During the transformation of VC into zkCredential, the restrictions of zkCredential should be taken into account.

> ## ZK Credential ecosystem

The ZK Credential is a protocol that serves as just one piece in a larger ecosystem, which will be built based on this protocol. Below is a description of the ecosystem - a global architecture, where ZK Credential plays a key role in the process of subject authentication without disclosing the subject's attributes.

### Basic terms

To start describing the ecosystem, it is necessary to introduce the basic terms:

`Subject` – entity that has a set of attributes in the digital area, it can be human, animal, things and etc.

`Super id` – identifier that refers to the subject in the digital. It constitutes a public key derived from a private key managed by the `frontend`

`zkCredential` – credentials serve as proof of subject attributes in the digital domain and must be issued by a trusted `issuer`. These credentials validate specific qualities or information about the `subject`.

`Issuer` –entity that has the capability to check `subject` attributes and issue zkCredentials. These credentials are designed to provide proof of specific attributes or qualities associated with the `subject`. The `issuer` plays a critical role in ensuring the authenticity and integrity of the credentials

`Decentralized storage` – entity that store data in decentralize manner. This means that the data is distributed across multiple nodes or devices rather than being stored in a centralized location

`Verifier` (other application) – entity that want to verify statement about `subject`

`Filter` – set of constraints that zkCredential has to be matched

`ZK credential proof` – cryptographic zk statement proving that `subject` has attributes in zkCredential that match to filter

`Frontend` – software application that run on the subject side, controlled by subject and can manage `super id`, communicate with `verifier`, `decentralized storage` and `issuer`. Also frontend can manage crypto wallets (other private keys)

`Proposal` – data structure that contains information about filter, zk credential proof receiver – verifier, super id. Subject can reject or accept verifier proposal. If subject accept proposal it generates zk credential proof by filter.

### Main Flow

Based on the definitions introduced above, the main flow is described as follows:

**Step 1**. `Verifier` wants to authenticate `subject`

**Step 2**. `Verifier` creates filter and execute request to `subject` (`frontend`)

**Step 3**.**1**. If `subject` reject proposal flow stops on this step.

**Step 3**.**2**. If `subject` has not zkCredential that can be matched to `filter`, `frontend` create request to `issuer` to issue appropriate zkCredential. After that `issuer` create zkCredential and send it to `subject`. When `frontend` receive zkCredential it encrypts it with private key from `super:id` symmetric cipher algorithm (e.g. AES), then save encrypted zkCredential in the `decentralized storage` and go to step 3.3.

**Step 3**.**3**. If `subject` already has encrypted zkCredential that can be matched to `filter` in `decentralized storage`, zkCredential has to be decrypted, after that `frontend` generate zkCredential proof, then go to step 4.

**Step 4**. `Frontend` send to verifier generated zkCredential proof

**Step 5**. `Verifier` verifies received zk proof and authenticates the `subject`.

The process described above is illustrated in the diagram below.

![ZKCredentialEcosistem.png](https://res.craft.do/user/full/89efce61-9b1d-0ff5-4eda-03346cd124c3/doc/daa894df-07f2-4185-baf0-759075935e53/9b06ccd2-0a4a-42dd-a4ef-2bc6edb2bd50)

Figure 2 - ZK Credential Ecosystem

### ZK Credential Proof Circuit

This section provides an overview of how ZK Credential Proof circuits work.

Statement: subject has attributes matched to filter in zkCredential issued by issuer with the public key.

**Private input**:

- zkCredential (issued by issuer)
- filter

**Public input**:

- issuer public key
- sign (signed zkCredential by issuer)

Diagram.

![Image.png](https://lh3.googleusercontent.com/zWVERGf9_uUGR_z2TPMUhrIAm5lLt7DRAQq4WYaSt1Sixl4yGWeubhgs_nEWPAtx8eLLuiQW5vTsuVvfob3IXeG6w8cehD0O3oLF-bHGENDVuGtEolRxUnshvkdtNsQ7Mc4_4P28G_iC)

**Limitation**

There is no unified sign algorithm, therefore for each blockchain issuer has to provide specific zkCredential

?descriptionFromFileType=function+toLocaleUpperCase()+{+[native+code]+}+File&mimeType=application/octet-stream&fileName=Zero+Knowledge+Credentials+v0.1+(status:+Draft).md&fileType=undefined&fileExtension=md