USE [signature_sys]
GO
/****** Object:  Table [dbo].[Document]    Script Date: 2025/5/27 18:22:35 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Document](
	[DocID] [varchar](36) NOT NULL,
	[UserID] [varchar](36) NOT NULL,
	[FileHash] [char](64) NULL,
	[Location] [varchar](256) NULL,
	[OriginalName] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[DocID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[Document] ([DocID], [UserID], [FileHash], [Location], [OriginalName]) VALUES (N'8caf5d88-0105-4b4c-8d99-515e5300b03f', N'2635c1a0-3ea3-49e5-8188-1cd2eb39b3fa', N'c6819247d23ee567054a613dd7cbb162116c7c13c4eea50445fe0a6779e8c484', N'static\docs\8caf5d88-0105-4b4c-8d99-515e5300b03f.pdf', N'token.pdf')
GO
ALTER TABLE [dbo].[Document]  WITH CHECK ADD FOREIGN KEY([UserID])
REFERENCES [dbo].[User] ([UserID])
GO
