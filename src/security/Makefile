obj-m += security.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

gui:
	gcc security_gui.c user_controller.c -o gui -lraylib -lGL -lm -lpthread -ldl -lrt -lX11

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean