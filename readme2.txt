HOWTO connect to Redis via ec2

step1 create Redis
step2 ec2 setup

ec2 -> security group -> Edit inbound rules 
add rule for Redis

step3 run the test at blow

sudo apt install gcc --option
sudo yum install gcc
wget http://download.redis.io/redis-stable.tar.gz
tar xvzf redis-stable.tar.gz
cd redis-stable
make distclean      // ubuntu systems only
make

src/redis-cli -c -h redan-redis.sh0mts.0001.apse1.cache.amazonaws.com -p 6379
src/redis-cli -c -h redis.oynbrd.ng.0001.apse1.cache.amazonaws.com -p 6379

HOWTO connect to Redis via docker

step1. install docker from the link
https://docs.docker.com/docker-for-windows/install/

step2. type this to install redis 
docker run -p 6379:6379 -d redis redis-server --appendonly yes

step3. connect to redis at localhost:6379

HOWTO shout down docker
step1. type the code at blow to list docker
docker ps

you may see some thing like this
c76e7c8dd1b9
b7te7c8asdfq

step2.stop docker by key
docker stop c76e7c8dd1b9
