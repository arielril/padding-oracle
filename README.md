# padding-oracle
Padding oracle attacker

## Installation

```sh
go install -v github.com/arielril/padding-oracle/cmd/paddingoracle@latest
```

## Running

### Installed package
```sh
λ paddingoracle -h

Padding oracle

Usage:
  paddingoracle [flags]

Flags:
   -msg, -message string  cipher message to attack
   -block-size int        block size (8, 16, 32) (default 16)
   -v, -verbose           verbose output
   -s, -silent            silent output
```

### Source code

```sh
go run cmd/paddingoracle/paddingoracle.go -h

Padding oracle

Usage:
  paddingoracle [flags]

Flags:
   -msg, -message string  cipher message to attack
   -block-size int        block size (8, 16, 32) (default 16)
   -v, -verbose           verbose output
   -s, -silent            silent output
```

### Examples

- Cipher message provided by the professor

```sh
paddingoracle -msg b30bd8c7be0c21847f69e71abc063e04842be3c899b2a9c96bc7f8b197187d218b9a1bfa82e0a992a04d1be7583826052a1fbe5836f8f3b7829a661598957826 -v
```


## Resources

> Papers
- https://www.usenix.org/legacy/event/woot10/tech/full_papers/Rizzo.pdf

> Blogs
- https://www.skullsecurity.org/2013/padding-oracle-attacks-in-depth
- https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
