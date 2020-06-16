FROM mcr.microsoft.com/dotnet/core/aspnet:3.1
ENV ASPNETCORE_URLS https://+:443
WORKDIR /app
COPY bin/Release/netcoreapp3.1/publish/ ./
ENTRYPOINT ["dotnet", "RegistrationAuthority.dll"]