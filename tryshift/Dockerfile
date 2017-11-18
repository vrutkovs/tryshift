FROM fedora:26

RUN dnf update -y && \
    dnf install -y python3-sqlalchemy hiredis && \
    dnf clean all

RUN pip3 install aiohttp aiohttp_security aiopg[sa] aiohttp_session aioredis

ADD tryshift/ /code
WORKDIR /code
#RUN pip3 install -r /code/requirements.txt
EXPOSE 8080

RUN ["python3", "/code/tryshift.py"]
