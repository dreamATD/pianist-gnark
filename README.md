# Pianist-gnark

This repo is an implementation of [Pianist](https://eprint.iacr.org/2023/1271) based on the library [gnark](https://github.com/ConsenSys/gnark).

## How to run the code

### Install Go
```
wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz # find the correct package on https://go.dev/dl/.
rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### On the same computer

Although Pianist is a zero-knowledge scheme deployed on a distributed system, it can be simulated on a single machine. In the case, the machine creates two processes and exchanges messages through ssh connection.

#### Configure SSH

1. install `openssh-server`
```
sudo apt install openssh-server
```

2. Configure ssh key
```
ssh-keygen -t rsa -b 4096
ssh-copy-id ${USER}@localhost
chmod go-w ~/
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

#### Clone the `dreamATD/pianist-gnark-crypto/` under the same directory as `/pianist-gnark`.
```
git clone git@github.com:dreamATD/pianist-gnark-crypto.git
```

#### Generate the `ip.txt`
Write a file containing the IP information in your cluster. Since here we use localhost to simulate two machines, we set different ports. Here is an example:
```
localhost:9998
localhost:9999
```

#### Configure the path of `ip.txt` and key files
In the `/pianist-gnark-crypto/ecc/bn254/fr/dkzg/dkzg.go`, configure `init()` function by the path of `ip.txt`, path of the private key used to log in the other machines and the username.

#### Run the code
Under `/pianist-gnark/examples/piano` (or `/pianist-gnark/examples/gpiano` if you want to run the version for general circuits), run the following command:
```
go run main.go
```

## Some clarification for the examples in `pianist-gnark/examples/piano` (and similar to `pianist-gnark/examples/gpiano`)
Showing the follosing output means it runs successfully:
```
[127.0.0.1 192.168.1.44 172.17.0.1]
rank 1 [127.0.0.1 192.168.1.44 172.17.0.1]

rank 1 [127.0.0.1 192.168.1.44 172.17.0.1]

Connected to slave 1
Sent working directory to slave 1

rank 1 Received buf size 60

rank 1 14:40:16 INF compiling circuit curve=bn254

rank 1 14:40:16 INF parsed circuit inputs nbPublic=2 nbSecret=1

14:40:16 INF compiling circuit curve=bn254
14:40:16 INF parsed circuit inputs nbPublic=2 nbSecret=1
14:40:16 INF building constraint system curve=bn254 nbConstraints=27999
rank 1 14:40:16 INF building constraint system curve=bn254 nbConstraints=27999

rank 1 Prover started

rank 1 14:40:18 DBG constraint system solver done backend=plonk curve=bn254 nbConstraints=27999 took=9.924368

rank 1 Solution computed

Prover started
14:40:18 DBG constraint system solver done backend=plonk curve=bn254 nbConstraints=27999 took=7.477513
Solution computed
rank 1 14:40:21 DBG prover done backend=piano curve=bn254 nbConstraints=27999 took=2195.654321

rank 1 Done

14:40:21 DBG verifier done backend=piano curve=bn254 took=6.606371
Done
```
