# Skimmer
Small, lightweight TCP port scanner

![](https://user-images.githubusercontent.com/9999745/45060279-2b6e4f80-b097-11e8-8fb6-5aba8936ab88.png)

# Usage

    -address string
          Address to scan
    -all
          Scan all possible ports (default true)
    -known
          Scan only well-known ports (0-1024)
    -private
          Scan private port range (49152-65535)
    -registered
          Scan registered port range (1024-49151)
    -threads int
          Number of threads to use when scanning (default 4)
    -timeout int
          Timeout for each connection attempt (default 1000)
