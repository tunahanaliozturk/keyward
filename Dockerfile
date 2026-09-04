# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build
WORKDIR /source

# Restore before the rest of the source is copied, so a change to a .cs file does not invalidate the
# restore layer. Only the files that actually decide the dependency graph are copied here.
# The .editorconfig comes along because it is part of the build, not a formatting preference:
# analyzer severities live in it, and the build treats warnings as errors.
COPY global.json .editorconfig Directory.Build.props Directory.Packages.props ./
COPY src/Keyward.Domain/Keyward.Domain.csproj src/Keyward.Domain/
COPY src/Keyward.Data/Keyward.Data.csproj src/Keyward.Data/
COPY src/Keyward.Host/Keyward.Host.csproj src/Keyward.Host/
RUN dotnet restore src/Keyward.Host/Keyward.Host.csproj

COPY src/ src/
RUN dotnet publish src/Keyward.Host/Keyward.Host.csproj \
    --configuration Release \
    --no-restore \
    --output /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS runtime
WORKDIR /app

# Runs as a non-root user. The image ships one, and the only reason services still run as root is that
# nobody changed the default.
USER $APP_UID

ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

COPY --from=build /app .

ENTRYPOINT ["dotnet", "Keyward.Host.dll"]
