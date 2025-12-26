USE [master]
GO

CREATE DATABASE [CredentialDb]
GO

USE [CredentialDb]
GO

CREATE TABLE [dbo].[HawkCredentials](
	[AuthId] [nvarchar](32) NOT NULL,
	[AuthKey] [nvarchar](128) NOT NULL,
	[HmacAlgorithm] [nvarchar](32) NOT NULL,
	[HashAlgorithm] [nvarchar](32) NOT NULL,
	[User] [nvarchar](32) NULL,
	[EnableServerAuthorization] [bit] NOT NULL,
	[IncludeResponsePayloadHash] [bit] NOT NULL,
	[CreatedTime] [datetime] NOT NULL,
 CONSTRAINT [PK_HawkCredentials] PRIMARY KEY CLUSTERED 
 (
	[AuthId] ASC
 )
)
GO

CREATE TABLE [dbo].[HmacCredentials](
	[AppId] [nvarchar](32) NOT NULL,
	[AppKey] [nvarchar](128) NOT NULL,
	[HmacAlgorithm] [nvarchar](32) NOT NULL,
	[HashAlgorithm] [nvarchar](32) NOT NULL,
	[CreatedTime] [datetime] NOT NULL,
 CONSTRAINT [PK_HmacCredentials] PRIMARY KEY CLUSTERED 
 (
	[AppId] ASC
 )
)
GO

INSERT INTO [dbo].[HawkCredentials]
           ([AuthId]
           ,[AuthKey]
           ,[HmacAlgorithm]
           ,[HashAlgorithm]
           ,[User]
           ,[EnableServerAuthorization]
           ,[IncludeResponsePayloadHash]
           ,[CreatedTime])
     VALUES
           ('id123'
           ,'3@uo45er?'
           ,'HMACSHA256'
           ,'SHA256'
           ,NULL
           ,0
           ,0
		   ,GETDATE())
GO

INSERT INTO [dbo].[HmacCredentials]
           ([AppId]
           ,[AppKey]
           ,[HmacAlgorithm]
           ,[HashAlgorithm]
           ,[CreatedTime])
     VALUES
           ('id123'
           ,'3@uo45er?'
           ,'HMACSHA256'
           ,'SHA256'
		   ,GETDATE())
GO