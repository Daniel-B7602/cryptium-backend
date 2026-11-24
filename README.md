# Cryptium — Backend

**Cryptium** es una plataforma web educativa y experimental orientada al aprendizaje, diseño, cifrado, análisis y criptoanálisis de construcciones criptográficas.

Este repositorio contiene el backend del sistema, responsable de exponer los servicios de la API, procesar las solicitudes del frontend y ejecutar las operaciones que requieren lógica del lado del servidor.

## Objetivo

Proporcionar una API que permita integrar las funcionalidades criptográficas de Cryptium con su interfaz web, facilitando el cifrado y descifrado de información, el procesamiento de archivos y el análisis experimental de diferentes técnicas criptográficas.

## Funcionalidades

- **Cifrado y descifrado de texto:** procesamiento de mensajes mediante algoritmos criptográficos.
- **Cifrado y descifrado de archivos:** recepción y procesamiento de archivos enviados desde el frontend.
- **Análisis criptográfico:** servicios para calcular estadísticas, estudiar frecuencias y evaluar características experimentales de los datos.
- **Análisis del efecto avalancha:** evaluación de los cambios producidos en los resultados criptográficos ante pequeñas modificaciones en la entrada.
- **Análisis de modos de bloque:** comparación experimental de patrones asociados a diferentes modos de cifrado.
- **Análisis antimalware:** integración con Microsoft Defender para analizar archivos en entornos Windows compatibles.
- **API REST:** comunicación entre el frontend y los servicios del backend mediante solicitudes HTTP.

*Las funcionalidades disponibles dependen de los controladores y servicios implementados en la versión actual del proyecto.*

## Tecnologías

- C#
- ASP.NET Core 8
- ASP.NET Core Web API
- .NET SDK
- Visual Studio Community

## Requisitos previos

- .NET SDK compatible con el proyecto.
- Git.
- Visual Studio Community o un editor compatible con proyectos .NET.
- Sistema operativo Windows para la funcionalidad de análisis con Microsoft Defender.

## Instalación y ejecución

### 1. Clonar el repositorio

```bash
git clone https://github.com/Daniel-B7602/cryptium-backend.git
```

### 2. Entrar en el directorio

```bash
cd cryptium-backend
```

### 3. Restaurar las dependencias

```bash
dotnet restore
```

### 4. Ejecutar la API

Desde la carpeta que contiene la solución, ejecuta:

```bash
dotnet run --project cryptium_backend/cryptium_backend.csproj
```

La dirección HTTPS y el puerto pueden variar según la configuración local del proyecto. Consulta la salida de la terminal para conocer la dirección en la que queda disponible la API.

## Integración con el frontend

El backend proporciona los servicios que consume la interfaz web de Cryptium. El frontend debe configurarse con la dirección de la API correspondiente al entorno de ejecución.

Durante el desarrollo local, ambos componentes deben ejecutarse y tener configurada correctamente la comunicación entre sus respectivos servidores.

## Estructura general

- `cryptium_backend/Controllers/`: controladores que reciben y gestionan las solicitudes HTTP.
- `cryptium_backend/Models/`: modelos utilizados para representar datos.
- `cryptium_backend/Services/`: servicios que implementan operaciones y lógica de procesamiento.
- `cryptium_backend/Properties/`: configuración del proyecto.
- `cryptium_backend/Program.cs`: configuración e inicio de la aplicación.
- `cryptium_backend/cryptium_backend.csproj`: definición del proyecto y sus dependencias.
- `cryptium_backend.sln`: solución de Visual Studio.

## Seguridad y configuración

- No publicar contraseñas, tokens, claves privadas ni credenciales.
- Mantener la configuración específica de desarrollo fuera del repositorio cuando contenga información sensible.
- Configurar correctamente los orígenes permitidos para las solicitudes del frontend.
- Utilizar HTTPS en los entornos que lo requieran.
- Verificar que los archivos recibidos sean procesados de forma segura.
