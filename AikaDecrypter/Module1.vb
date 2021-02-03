Imports System.Security.Cryptography
Imports System.Reflection
Imports dnlib.DotNet
Imports System.IO
Imports System.Text

Module Module1

    Sub Main(ByVal args As String())
        Console.Title = "UNPAika v1.0"
        Console.WriteLine("UNPAika v1.0 by misonothx - Decrypter & Unpacker for Aika Crypter")
        Console.WriteLine()
        Dim asm As Assembly
        Try
            asm = Assembly.LoadFile(Path.GetFullPath(args(0)))
        Catch ex As Exception
            Console.ForegroundColor = ConsoleColor.DarkRed
            Console.Write("Invalid file, please make sure the input file is a protected executable.")
            Console.ReadKey()
            End
        End Try
        Dim patchedApp As dnlib.DotNet.ModuleDef = dnlib.DotNet.ModuleDefMD.Load(args(0))
        Dim types As New List(Of String)
        Dim methods As New List(Of String)
        Dim key, hasAntiVM, isNative, SelfInj, Startup
        For x = 0 To patchedApp.Types.Count - 1
            types.Add(patchedApp.Types(x).ToString)
        Next
        For x = 0 To patchedApp.Types(types.IndexOf("Aika_Crypter.Program")).Methods.Count - 1
            methods.Add(patchedApp.Types(types.IndexOf("Aika_Crypter.Program")).Methods(x).ToString.Split("::")(2))
        Next
        For x = 0 To patchedApp.Types(types.IndexOf("Aika_Crypter.Program")).Methods(methods.IndexOf(".cctor()")).Body.Instructions.Count - 1
            Dim currentInstruction As dnlib.DotNet.Emit.Instruction = patchedApp.Types(types.IndexOf("Aika_Crypter.Program")).Methods(methods.IndexOf(".cctor()")).Body.Instructions(x)
            If currentInstruction.OpCode.ToString = "ldstr" Then
                key = currentInstruction.Operand.ToString
            ElseIf currentInstruction.OpCode.ToString.Contains("ldc.i4") Then
                Select Case patchedApp.Types(types.IndexOf("Aika_Crypter.Program")).Methods(methods.IndexOf(".cctor()")).Body.Instructions(x + 1).Operand.ToString().Split("::")(2)
                    Case "Startup"
                        Startup = CBool(currentInstruction.OpCode.ToString.Replace("ldc.i4.", Nothing))
                    Case "IsNative"
                        isNative = CBool(currentInstruction.OpCode.ToString.Replace("ldc.i4.", Nothing))
                    Case "SelfInj"
                        SelfInj = CBool(currentInstruction.OpCode.ToString.Replace("ldc.i4.", Nothing))
                    Case "AntiVM"
                        hasAntiVM = CBool(currentInstruction.OpCode.ToString.Replace("ldc.i4.", Nothing))
                End Select
            End If
        Next
        Console.ForegroundColor = ConsoleColor.Magenta
        Console.WriteLine("Encryption Password: " & key)
        Console.ForegroundColor = ConsoleColor.Cyan
        Console.WriteLine()
        Console.WriteLine("-- Protections --")
        Console.WriteLine("AntiVM?: " & hasAntiVM.ToString)
        Console.WriteLine("Native?: " & isNative.ToString)
        Console.WriteLine("Self Injection?: " & SelfInj.ToString)
        Console.WriteLine("Run On Startup?: " & Startup.ToString)
        Console.ForegroundColor = ConsoleColor.Yellow
        Dim ms As New MemoryStream()
        Dim resNames As New List(Of String)
        resNames = asm.GetManifestResourceNames().ToList
        asm.GetManifestResourceStream("payload").CopyTo(ms)
        Console.WriteLine()
        Console.WriteLine("Extracting Payload...")
        If Not Directory.Exists("UNPAika") Then
            Directory.CreateDirectory("UNPAika")
        End If
        Directory.CreateDirectory("UNPAika\" & Path.GetFileNameWithoutExtension(args(0)))
        Console.WriteLine()
        Try
            File.WriteAllBytes("UNPAika\" & Path.GetFileNameWithoutExtension(args(0)) & "\payload.bin", Decrypt(ms.ToArray(), key))
        Catch ex As Exception
            Console.ForegroundColor = ConsoleColor.DarkRed
            Console.WriteLine("Failed to extract Payload (exception: " & ex.Message & ")")
            Console.ReadKey()
            End
        End Try
        Console.ForegroundColor = ConsoleColor.Green
        Console.WriteLine("Successful extraction. Press any key to close the application")
        Console.ReadKey()
    End Sub

    Private Function Decrypt(ByVal encrypted As Byte(), ByVal key As String) As Byte()
        Dim result As Byte() = Nothing
        Dim rfc2898DeriveBytes As Rfc2898DeriveBytes = New Rfc2898DeriveBytes(Encoding.ASCII.GetBytes(key), Encoding.ASCII.GetBytes(key), 1000)
        Using aes As Aes = New AesManaged()
            aes.KeySize = 256
            aes.Key = rfc2898DeriveBytes.GetBytes(aes.KeySize / 8)
            aes.IV = rfc2898DeriveBytes.GetBytes(aes.BlockSize / 8)
            Using memoryStream As MemoryStream = New MemoryStream()
                Using cryptoStream As CryptoStream = New CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write)
                    cryptoStream.Write(encrypted, 0, encrypted.Length)
                    cryptoStream.Close()
                End Using
                result = memoryStream.ToArray()
            End Using
        End Using
        Return result
    End Function

End Module
