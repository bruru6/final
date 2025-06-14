USE [signature_sys]
GO
/****** Object:  Table [dbo].[SignLog]    Script Date: 2025/5/27 18:22:35 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SignLog](
	[LogID] [bigint] IDENTITY(1,1) NOT NULL,
	[UserID] [varchar](36) NOT NULL,
	[DocID] [varchar](36) NOT NULL,
	[SealID] [varchar](36) NOT NULL,
	[CertID] [varchar](36) NOT NULL,
	[SignAlgorithm] [varchar](10) NULL,
	[SignatureValue] [varbinary](2048) NULL,
	[PositionX] [float] NULL,
	[PositionY] [float] NULL,
	[Scale] [float] NULL,
	[Rotation] [int] NULL,
	[SignTime] [datetime] NULL,
PRIMARY KEY CLUSTERED 
(
	[LogID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[SignLog] ON 

INSERT [dbo].[SignLog] ([LogID], [UserID], [DocID], [SealID], [CertID], [SignAlgorithm], [SignatureValue], [PositionX], [PositionY], [Scale], [Rotation], [SignTime]) VALUES (55, N'2635c1a0-3ea3-49e5-8188-1cd2eb39b3fa', N'8caf5d88-0105-4b4c-8d99-515e5300b03f', N'2cf57505-b629-4170-98b5-2976d05c1822', N'6362d574-db35-42be-814f-96916a4ff460', N'pyHanko', NULL, 185.67, 354.33, 0.2308, 61, CAST(N'2025-05-27T18:06:11.153' AS DateTime))
INSERT [dbo].[SignLog] ([LogID], [UserID], [DocID], [SealID], [CertID], [SignAlgorithm], [SignatureValue], [PositionX], [PositionY], [Scale], [Rotation], [SignTime]) VALUES (56, N'2635c1a0-3ea3-49e5-8188-1cd2eb39b3fa', N'8caf5d88-0105-4b4c-8d99-515e5300b03f', N'2cf57505-b629-4170-98b5-2976d05c1822', N'6362d574-db35-42be-814f-96916a4ff460', N'pyHanko', NULL, 40, 80, 0.2308, 0, CAST(N'2025-05-27T18:11:58.700' AS DateTime))
SET IDENTITY_INSERT [dbo].[SignLog] OFF
GO
ALTER TABLE [dbo].[SignLog]  WITH CHECK ADD FOREIGN KEY([DocID])
REFERENCES [dbo].[Document] ([DocID])
GO
ALTER TABLE [dbo].[SignLog]  WITH CHECK ADD FOREIGN KEY([SealID])
REFERENCES [dbo].[Seal] ([SealID])
GO
ALTER TABLE [dbo].[SignLog]  WITH CHECK ADD FOREIGN KEY([UserID])
REFERENCES [dbo].[User] ([UserID])
GO
ALTER TABLE [dbo].[SignLog]  WITH CHECK ADD CHECK  (([Rotation]>=(0) AND [Rotation]<=(360)))
GO
ALTER TABLE [dbo].[SignLog]  WITH CHECK ADD CHECK  (([Scale]>=(0.2) AND [Scale]<=(2.0)))
GO
