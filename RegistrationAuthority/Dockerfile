FROM mcr.microsoft.com/dotnet/core/aspnet
WORKDIR /app
COPY bin/Release/netcoreapp3.1/publish/ ./
#RUN chmod 777 ./RegistrationAuthority
ENTRYPOINT ["./RegistrationAuthority"]