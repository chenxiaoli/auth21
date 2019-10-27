FROM registry.cn-hangzhou.aliyuncs.com/chenxl/python3.6
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
COPY . /usr/src/app
RUN pip install --no-cache-dir -r requirements.txt
RUN export DJANGO_SETTINGS_MODULE="auth21.settings_dev"
CMD ["python", "./manage.py","runserver","0.0.0.0:8000" ]
