# PEHeaderViewer
A PHP script that dumps the PE Header of a Windows PE (executable) file

## Information obtained:

#### COFF File Header
- Machine 
- Signature 
- NumberOfSections 
- TimeDateStamp 
- SizeOfOptionalHeader 
- Characteristics 

#### Optional Header
- SizeOfCode 
- SizeOfInitializedData
- SizeOfUninitializedData
- AddressOfEntryPoint 
- BaseOfCode 
- BaseOfData 
- ImageBase 
- ImportDirectoryRVA 
- ImportDirectorySize 
- ResourceDirectoryRVA 
- ResourceDirectorySize 
- IATDirectoryRVA 
- IATDirectorySize 

#### Section of IAT

#### Imported dlls

#### List of all sections
- Virtual Size
- Virtual Address	
- RawSize	
- RawAddress	
- Characteristics

#### Content dump of each section (ASCII and HEX)

#### UPX Detection

## Usage:
Change the variable ```php $arquivo``` on line 3 to the path+file of the file you want to analyze. If the file is at the same folder as the PHP script, simply put its name (file.exe).
