FROM mcr.microsoft.com/dotnet/core/runtime-deps
ENV ASPNETCORE_URLS="https://+"
ENV ASPNETCORE_HTTPS_PORT=8011
ENV ASPNETCORE_Kestrel__Certificates__Default__Password="test"
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/ServerCert.pfx
WORKDIR /app
COPY bin/Release/netcoreapp3.1/publish/ ./
ENTRYPOINT ["./Certificationauthority"]