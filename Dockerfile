FROM nlnetlabs/pythonunbound
RUN apt-get -y update && apt-get -y install wget git
RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python3.6 get-pip.py
RUN pip install pandas pytrie
RUN cp unbound.conf unbound.conf.org
ADD dlookup.py ./
ADD threatlist.csv ./
ADD unbound.conf ./
