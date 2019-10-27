
local test

git pull origin
git checkout develop
docker build --tag=auth21 .
docker stop hlwy-auth
docker rm hlwy-auth
docker run --name hlwy-auth -p 18000:8000 -d  -v /var/data/hlwy-auth:/usr/src/app auth21

docker run -it --rm  --link mysql:mysql -v  /var/data/hlwy-auth:/usr/src/app auth21 python ./manage.py makemigrations
docker run -it --rm  --link mysql:mysql -v  /var/data/hlwy-auth:/usr/src/app auth21 python ./manage.py migrate

docker run -it --rm  --link mysql:mysql -v  /var/data/hlwy-auth:/usr/src/app auth21 python ./manage.py create

docker run -it --rm -p 18000:8000  --link mysql:mysql -v  /var/data/hlwy-auth:/usr/src/app auth21

docker run -it --rm  --link mysql:mysql -v  e:/code/auth21:/usr/src/app auth21 python ./manage.py makemigrations
docker run -it --rm  --link mysql:mysql -v  e:/code/auth21:/usr/src/app auth21 python ./manage.py migrate
docker run -it --rm  --link mysql:mysql -v e:/code-example/propertymgtwx:/usr/src/app hltest-wxfront:develop python ./manage.py import_customer


docker run --name auth21 -p 8101:8000 -d --link mysql:mysql -v e:/code/auth21:/usr/src/app auth21
