Malloc can be tested with any application by using:
LD_PRELOAD=./malloc.so

For example: LD_PRELOAD=./malloc.so xeyes

To see debug messages add: MALLOC_DEBUG=1
