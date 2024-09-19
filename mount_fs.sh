cd $(pwd)
mkdir fs 
cd fs
 cpio -idv <../rootfs_updated.cpio #마운트
 cd ../

