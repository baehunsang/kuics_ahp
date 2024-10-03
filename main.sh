#! /bin/bash
if [ ! -e "exploit" ]; then
    mkdir exploit
fi
echo "Enter the link to your exploit"
echo "File formate: exploit.tar.gz"
echo "> "
read link

wget -O exploit.tar.gz $link

if [ ! -e "exploit.tar.gz" ]; then
    exit
fi


chmod 777 ./exploit.tar.gz

tar -zxvf ./exploit.tar.gz

mkdir fs
cd fs
cpio -idv <../rootfs.cpio 
cd ../

cp ./exploit/* ./fs/

#upload
cd ./fs
find . -print0 | cpio -o --format=newc --null  > ../rootfs_updated.cpio
cd ../

rm -rf ./fs
rm -rf ./exploit
rm exploit.tar.gz

qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr" \
    -no-reboot \
    -cpu qemu64,+smap,+smep\
    -smp 2 \
    -monitor /dev/null \
    -initrd ./rootfs_updated.cpio \
    -net nic,model=virtio \
    -net user 

rm -rf rootfs_updated.cpio

