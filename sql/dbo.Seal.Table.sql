USE [signature_sys]
GO
/****** Object:  Table [dbo].[Seal]    Script Date: 2025/5/27 18:22:35 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Seal](
	[SealID] [varchar](36) NOT NULL,
	[UserID] [varchar](36) NOT NULL,
	[ImageHash] [char](64) NULL,
	[Location] [varchar](256) NULL,
PRIMARY KEY CLUSTERED 
(
	[SealID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[Seal] ([SealID], [UserID], [ImageHash], [Location]) VALUES (N'2cf57505-b629-4170-98b5-2976d05c1822', N'2635c1a0-3ea3-49e5-8188-1cd2eb39b3fa', N'36c5ec4f48a438d542b3e189b5512c0e75df2d151cd4786264d9d46bf53a8956', N'static\seals\2cf57505-b629-4170-98b5-2976d05c1822.png')
GO
ALTER TABLE [dbo].[Seal]  WITH CHECK ADD FOREIGN KEY([UserID])
REFERENCES [dbo].[User] ([UserID])
GO
