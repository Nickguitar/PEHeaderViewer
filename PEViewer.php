<?php

$arquivo = "xampp_start.exe"; // executable to be analyzed
$fp = fopen($arquivo, "r");
$hex = strtoupper(bin2hex(fread($fp, filesize($arquivo))));
$MZ = substr($hex, 0, 4);
$DpsPE = explode("5045", $hex); //split the PE header from the rest 
$PE = array( //storage the PE header
	"Machine" => substr($DpsPE[1], 0, 8), 
	"Signature" => hexdec(mudaEndianess(substr($DpsPE[1], 44, 4))),
	"NumberOfSections" => mudaEndianess(substr($DpsPE[1], 8, 4)),
	"TimeDateStamp" => date("d/m/Y - H:i:s", hexdec(substr($DpsPE[1], 13,8))),
	"SizeOfOptionalHeader" => mudaEndianess(substr($DpsPE[1], 36,4)),
	"Characteristics" => mudaEndianess(substr($DpsPE[1], 40, 4)),
	"SizeOfCode" => mudaEndianess(substr($DpsPE[1], 52, 8))."h",
	"SizeOfInitializedData" => mudaEndianess(substr($DpsPE[1], 60, 8))."h",
	"SizeOfUninitializedData" => mudaEndianess(substr($DpsPE[1], 68, 8))."h",
	"AddressOfEntryPoint" => mudaEndianess(substr($DpsPE[1], 74, 8)),
	"BaseOfCode" => mudaEndianess(substr($DpsPE[1], 82, 8)),
	"BaseOfData" => mudaEndianess(substr($DpsPE[1], 90, 8)),
	"ImageBase" => mudaEndianess(substr($DpsPE[1], 98, 8)),
	//DataDirectory
	"ImportDirectoryRVA" => mudaEndianess(substr($DpsPE[1], 252, 8)),
	"ImportDirectorySize" => mudaEndianess(substr($DpsPE[1], 260, 8)),
	"ResourceDirectoryRVA" => mudaEndianess(substr($DpsPE[1], 268, 8)),
	"ResourceDirectorySize" => mudaEndianess(substr($DpsPE[1], 276, 8)),
	
	"IATDirectoryRVA" => mudaEndianess(substr($DpsPE[1], 428, 8)),
	"IATDirectorySize" => mudaEndianess(substr($DpsPE[1], 436, 8))
);

foreach($PE as $item => $valor){
	echo $item." => ".$valor."<br>";
}
if(strpos(hex2str(substr($DpsPE[1], 492, 80*$PE["NumberOfSections"])),"UPX") !== false){
	$ptr_secoes = split("2E", substr($DpsPE[1], 492, 80*$PE["NumberOfSections"]));
	$sec = 1;
	echo "Se&ccedil;&atilde;o do UPX encontrada"; //upx found
}else{
	$ptr_secoes = explode("2E", substr($DpsPE[1], 492, 80*$PE["NumberOfSections"]));
	$sec = $PE["NumberOfSections"];
}

echo "<script type='text/javascript' src='http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js'>
</script>

<script type='text/javascript'>

 $(document).ready(function() { 
   $('input[name=modo]').change(function(){
        $('form').submit();
   });
  });

</script>";

echo "<br><br><style>#tabela td{padding:10px;text-align:center;}#content{width:700px;height:200px;}</style><table id='tabela' border='1'><tr><td>Nome</td><td>Virtual Size</td><td>Virtual Address</td><td>RawSize</td><td>RawAddress</td><td>Characteristics</td><td>Conte&uacute;do <form action=''>
";
$ascii = false;
$Hex = false;
$asm = false;
if(!isset($_GET["modo"])){
	$modo = "ascii";
}else{
	$modo = $_GET["modo"];
}
	if($modo == "ascii"){
		$ascii = TRUE;
		echo "<input type='radio' id='ascii' name='modo' value='ascii' checked='checked'>ASCII ";
		echo "<input type='radio' id='hex' name='modo' value='hex'>HEX ";
	}
	if($modo == "hex"){
		$Hex = TRUE;
		echo "<input type='radio' id='ascii' name='modo' value='ascii'>ASCII ";
		echo "<input type='radio' id='hex' name='modo' value='hex'  checked='checked'>HEX ";
	}

echo "</form></td></tr>";
for($i=1;$i<=$sec;$i++){
	$nomeSecao = ".".hex2str(strstr($ptr_secoes[$i], "00", TRUE));
	$VirtualSize = mudaEndianess(substr($ptr_secoes[$i], 14,8));
	$VirtualAddress = mudaEndianess(substr($ptr_secoes[$i], 22,8));
	$RawSize = mudaEndianess(substr($ptr_secoes[$i], 30,8));
	$RawAddress = mudaEndianess(substr($ptr_secoes[$i], 38,8));
	$Characteristics = mudaEndianess(substr($ptr_secoes[$i], 70,8));
	$Conteudo = substr($hex, 2*hexdec($RawAddress), 2*hexdec($RawSize));
	$IAT = "";
	foreach($PE as $teste => $valor){
		if($teste == "IATDirectoryRVA"){
			if($valor <> "00000000"){
				if($VirtualAddress == $valor){
					$IAT = $nomeSecao;
					echo "IAT encontrada em : ".$nomeSecao."<br><br>";
				}
			}
		}
		if($teste == "ImportDirectoryRVA"){
			if($VirtualAddress == $valor){
				$IAT = $nomeSecao;
				echo "IAT encontrada em: ".$nomeSecao."<br><br>";
			}
		}
	}
	if($nomeSecao == $IAT){
	
		echo "	<tr style='margin:3px;'>
				<td>".$nomeSecao."</td>
				<td>".$VirtualSize."h</td>
				<td>".$VirtualAddress."h</td>
				<td>".$RawSize."h</td>
				<td>".$RawAddress."h</td>
				<td>".$Characteristics."h</td>
				";
				if($ascii){
					echo "<td><textarea id='content'>".hex2str_imports($Conteudo)."</textarea></td>";
				}
				if($Hex){
					echo "<td><textarea id='content'>".($Conteudo)."</textarea></td>";
				}
				pegaDll(hex2str_imports($Conteudo));
				echo "</tr>";
	}else{
		echo "	<tr style='margin:3px;'>
				<td>".$nomeSecao."</td>
				<td>".$VirtualSize."h</td>
				<td>".$VirtualAddress."h</td>
				<td>".$RawSize."h</td>
				<td>".$RawAddress."h</td>
				<td>".$Characteristics."h</td>
				";
				if($ascii){
					echo "<td><textarea id='content'>".hex2str($Conteudo)."</textarea></td>";
				}
				if($Hex){
					echo "asd";
					echo "<td><textarea id='content'>".($Conteudo)."</textarea></td>";
				}
				echo "</tr>";
	} 
	
}echo "</table>";
echo "<br><bR>";

// =================== Funções e verificação ===================

if($MZ <> "4D5A"){
	die("N&atilde;o é um arquivo execut&aacute;vel.");
}

if($PE["Signature"] <> 267){
	die("N&atilde;o é um arquivo PE.");
}

function pegaDll($secao){ //get used dlls
	$imports = explode("#", $secao);
	foreach($imports as $dll){
		if(strlen($dll) > 6){
			if(strpos(strtolower($dll), ".dll") !== false){
				if(strpos($dll, "*") !== false or strpos($dll, "\\") !== false){
				}else{
					echo strtolower($dll)."<br>";
				}
			}
		}
	}
}

function pegaFuncao($secao){ //get some Windows functions called
	echo "<br><br>";
	$imports = split("#", $secao);
	$funcoes = array();
	foreach($imports as $dll){
		if(strlen($dll) > 6){
			if(!strpos($dll, ".") !== false){
				array_push($funcoes, $dll);
			}
		}
	}
	sort($funcoes);
	foreach($funcoes as $dado){
		echo $dado."<br>";
	}
}

function mudaEndianess($hex){ 
    return implode('', array_reverse(str_split($hex, 2)));
}

function hex2str2($hex) { //transforma tudo pra texto, mas deixa o texto zuado
			$str = '';
			$hex = str_replace(" ", "", $hex);
			for($i=0;$i<strlen($hex);$i+=2) {
				$decValue = hexdec(substr($hex,$i,2));
				if($decValue > 32) {
					$str .= mb_convert_encoding(chr($decValue), 'UTF-8', 'ISO-8859-2');
				}
			}
	return $str;
}

// i coded this shit so long ago that i don't remember what is the real difference between this functions lol

function hex2str_imports($hex) { //transforma tudo pra texto, mas deixa o texto zuado
	$str = '';
	$hex = str_replace(" ", "", $hex);
	for($i=0;$i<strlen($hex);$i+=2) {
		$decValue = hexdec(substr($hex,$i,2));
		if($decValue > 32) {
			$str .= mb_convert_encoding(chr($decValue), 'UTF-8', 'ISO-8859-2');
		}else{
			$str .= "#";
		}
	}
	return $str;
}
