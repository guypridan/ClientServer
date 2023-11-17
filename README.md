# Client-Server Communication Project

## Overview

This repository contains a client-server communication project developed for the Defensive System Design course at Open University. The project implements a TCP-based network protocol with a predefined packet format for communication between a C++ client and a Python server.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Protocol Details](#protocol-details)

## Installation

### Prerequisites

- Windows operating system
- #### for the client
- Visual Studio Code
- C++ compiler with C++17 support
- C++ CryptoPP lib
- #### for the server
- Python interpreter 
- Python PyCryptoDome lib 

### Clone the Repository

```bash
git clone https://github.com/your-username/client-server-project.git
cd client-server-project
```

### Build the C++ Client
1. Open Visual Studio Code.
2. Open the project folder in Visual Studio Code.
3. Install the C/C++ extension if not already installed.
4. Download Cryptopp lib from [Link Text](https://www.cryptopp.com/#download) 
5. compile the Cryptopp lib and make a static link to it in the Visual Studio project
6. build.


### Install Python Dependencies for the Server
```bash
cd ../server
pip install pycryptodome
```

## Usage
1. ### Start the server
```bash
cd server
py server.py
```
The server will start listening for incoming connections on the specified port.
2. Run the client
The client will establish a connection to the server and begin communication.
