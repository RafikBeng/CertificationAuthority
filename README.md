# Certification Authority

A PKI (Public Key Infrastructure) system built with ASP.NET Core, providing certificate issuance, management, and revocation through a two-tier CA/RA architecture backed by MongoDB.

![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)
![C#](https://img.shields.io/badge/C%23-57%25-239120?logo=csharp)
![MongoDB](https://img.shields.io/badge/MongoDB-Driver_2.19-47A248?logo=mongodb)
![Build](https://img.shields.io/github/actions/workflow/status/RafikBeng/CertificationAuthority/dotnet.yml?branch=master)
![Release](https://img.shields.io/github/v/release/RafikBeng/CertificationAuthority)

---

## Overview

This project implements a classic two-tier PKI model:

- **Certification Authority (CA)** — issues, signs, and revokes X.509 certificates using the BouncyCastle cryptography library.
- **Registration Authority (RA)** — a web-facing front-end that handles certificate requests from end users, validates identity, and forwards approved requests to the CA.
- **Certlib** — a shared class library that encapsulates core certificate logic (key generation, CSR handling, signing, CRL management) reused by both the CA and RA.
- **UnitTest** — an automated test project covering the core certificate operations.

---

## Solution Structure

```
CertificationAuthority.sln
├── Certlib/                    # Shared PKI library (key pairs, CSR, signing, CRL)
├── Certificationauthority/     # CA web application (ASP.NET Core + MongoDB)
├── RegistrationAuthority/      # RA web application (ASP.NET Core + MongoDB + jQuery UI)
└── UnitTest/                   # Unit tests for Certlib
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Framework | ASP.NET Core (.NET 8) |
| Language | C# |
| Cryptography | BouncyCastle |
| Database | MongoDB (Driver 2.19) |
| Frontend | HTML, CSS, jQuery UI |
| Testing | .NET Unit Test project |
| CI/CD | GitHub Actions |

---

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8)
- [MongoDB](https://www.mongodb.com/try/download/community) (local instance or Atlas connection string)

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/RafikBeng/CertificationAuthority.git
cd CertificationAuthority
```

### 2. Configure MongoDB connection strings

In both `Certificationauthority/appsettings.json` and `RegistrationAuthority/appsettings.json`, set your MongoDB connection:

```json
{
  "MongoDB": {
    "ConnectionString": "mongodb://localhost:27017",
    "DatabaseName": "CertificationAuthority"
  }
}
```

### 3. Restore and build

```bash
dotnet restore
dotnet build --configuration Release
```

### 4. Run the CA

```bash
cd Certificationauthority
dotnet run
```

### 5. Run the RA (separate terminal)

```bash
cd RegistrationAuthority
dotnet run
```

---

## Running Tests

```bash
dotnet test UnitTest/UnitTest.csproj
```

---

## CI/CD

The repository uses GitHub Actions for continuous integration and delivery. On every push to `master`:

1. Dependencies are restored
2. The solution is built in Release mode
3. The output is published and zipped
4. A new GitHub Release is created automatically with the build artifact

The workflow file is located at `.github/workflows/dotnet.yml`.

---

## Dependencies

| Package | Used In |
|---|---|
| `BouncyCastle.dll` | Certlib — X.509 certificate and key operations |
| `MongoDB.Driver 2.19` | Certificationauthority, RegistrationAuthority |
| `jQuery UI 1.13+` | RegistrationAuthority frontend |

---

## Architecture

```
 [ End User / Browser ]
         │
         ▼
 [ Registration Authority ]   ←── Validates identity, collects CSR
         │
         ▼
 [ Certification Authority ]  ←── Signs certificate, manages CRL
         │
         ▼
     [ MongoDB ]              ←── Stores certificates, requests, revocation list
```

---

## License

This project is not currently under an open-source license. All rights reserved by the author.

---

## Author

**RafikBeng** — [github.com/RafikBeng](https://github.com/RafikBeng)

