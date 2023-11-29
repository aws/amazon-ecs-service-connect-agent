# FROM 894069144441.dkr.ecr.us-west-2.amazonaws.com/aws-appmesh-envoy:v1.27.0.1-test-prof
FROM 840364872350.dkr.ecr.us-west-2.amazonaws.com/aws-appmesh-envoy:v1.27.2.0-prod

ADD agent /usr/bin/agent

RUN chmod +x /usr/bin/agent && \
    setcap CAP_SETPCAP,CAP_NET_ADMIN+p /usr/bin/agent

CMD [ "/usr/bin/agent" ]