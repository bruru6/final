USE [signature_sys]
GO
/****** Object:  Table [dbo].[Cert]    Script Date: 2025/5/27 18:22:35 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Cert](
	[CertID] [varchar](36) NOT NULL,
	[UserID] [varchar](36) NOT NULL,
	[Location] [varchar](256) NULL,
	[IssuerDN] [varchar](255) NULL,
	[ValidFrom] [datetime] NULL,
	[ValidTo] [datetime] NULL,
	[PublicKey] [text] NULL,
	[Algo] [varchar](10) NULL,
PRIMARY KEY CLUSTERED 
(
	[CertID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
INSERT [dbo].[Cert] ([CertID], [UserID], [Location], [IssuerDN], [ValidFrom], [ValidTo], [PublicKey], [Algo]) VALUES (N'6362d574-db35-42be-814f-96916a4ff460', N'2635c1a0-3ea3-49e5-8188-1cd2eb39b3fa', N'static\certs\6362d574-db35-42be-814f-96916a4ff460.pem', N'CN=User ECC Cert', CAST(N'2025-05-27T17:34:27.320' AS DateTime), CAST(N'2030-05-27T17:34:27.320' AS DateTime), N'-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwGyLawOeHNmKBtip62fRxaCssMrT
KTvugoCX+YyW5jgy9IGYDfbRlphmU1/J/54IMfuhLLKaJXppF2019lknpQ==
-----END PUBLIC KEY-----
', N'ECC')
INSERT [dbo].[Cert] ([CertID], [UserID], [Location], [IssuerDN], [ValidFrom], [ValidTo], [PublicKey], [Algo]) VALUES (N'e152c413-05ee-400f-8158-0af10bd2a3eb', N'2635c1a0-3ea3-49e5-8188-1cd2eb39b3fa', N'static\certs\e152c413-05ee-400f-8158-0af10bd2a3eb.pem', N'CN=User RSA Cert', CAST(N'2025-05-27T17:34:27.320' AS DateTime), CAST(N'2030-05-27T17:34:27.320' AS DateTime), N'-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8cluUvGPsTDEXadJ1F/z
9hubtZtDzxWrH39C2kwuxkaEfgyaU3ATdmOCbUO0PoCS/Vvz+/zZCoplgfj+vbPw
nKJ1eo/jSM383gWpSHgyf6F2CiA0hUnjp8JFHhRF4P75ZXrR5HXko7nI0wkgg8/U
XQBETEaufPUrbOhkYRAfYURf+60w6kWuTsgTvqnTIK5FeGy1i3XVdPaWP7r+n1sv
vMMsGpVFqOBF2zzxOO2UuEZtu57wytvDV/eGIM7oP0iLe/xjAfPDiWZmK8CCH7pG
cqmJD2acSR/0l2yh/r83gvRMIciWKjIRVwf3mLpTnPHUJMoEED/V4QNYPv+lRi59
dwIDAQAB
-----END PUBLIC KEY-----
', N'RSA')
GO
ALTER TABLE [dbo].[Cert]  WITH CHECK ADD FOREIGN KEY([UserID])
REFERENCES [dbo].[User] ([UserID])
GO
