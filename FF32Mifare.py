######################################################################################
#
#  FF32Mifare.py
#  Programa em Python para comunicar com o leitor Mifare MFRC522 da NXP
#  através de um chip FF32 com conversão do tipo USB->SPI
#  By   : Erik Figueiredo
#  Date : 10-03-2015
#  Rev  : 0.1
#  
#  utiliza: pyff32.py   Biblioteca de comunicação FF32
#
#  O código foi testado em um Raspberry Pi --[USB]-->FF32--[SPI]-->RC522
#  Diversas placas RC522 estão disponíveis no mercado chinês. Por mais que os conectores estejam mapeados como SS/SCK/MOSI/MISO, a placa pode suportar comunicação I2C ou UART.
#  A melhor forma de garantir que tipo de protocolo utilia, é checando a voltagem do pin #1 (0 volt) e pin #32 (3.3 volts), para saber se é SPI
#  
#  Para mais detalhes do microcontrolador MFRC522, leia o datasheet: http://www.nxp.com/documents/data_sheet/MFRC522.pdf
#
#######################################################################################

import pyff32
import signal
import time
  
class FF32Mifare:
  NRSTPD = 22
  
  MAX_LEN = 16

  PCD_IDLE       = 0x00  # nenhuma ação, cancela a execução do comando atual
  PCD_MEM        = 0x01  # armazena 25 bytes dentro do buffer interno
  PCD_GEN_RND_ID = 0x02  # gera um número ID sortido de 10 bytes
  PCD_CALC_CRC   = 0x03  # activates the CRC coprocessor or performs a self test
  PCD_TRANSMIT   = 0x04  # transmits data from the FIFO buffer
  PCD_NO_CMD	 = 0x07  # no command change, can be used to modify the CommandReg register bits without affecting the command, for example, the PowerDown bit
  PCD_RECEIVE    = 0x08  # activates the receiver circuits
  PCD_TRANSCEIVE = 0x0C  # transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
  PCD_AUTHENT    = 0x0E  # executa autenticação como leitor no padrão MIFARE
  PCD_RESETPHASE = 0x0F  # reseta o RC522

  
  PICC_REQIDL    = 0x26
  PICC_REQALL    = 0x52
  PICC_ANTICOLL  = 0x93
  PICC_SElECTTAG = 0x93
  PICC_AUTHENT1A = 0x60
  PICC_AUTHENT1B = 0x61
  PICC_READ      = 0x30
  PICC_WRITE     = 0xA0
  PICC_DECREMENT = 0xC0
  PICC_INCREMENT = 0xC1
  PICC_RESTORE   = 0xC2
  PICC_TRANSFER  = 0xB0
  PICC_HALT      = 0x50
  
  MI_OK       = 0
  MI_NOTAGERR = 1
  MI_ERR      = 2
  
  Reserved00     = 0x00
  CommandReg     = 0x01
  CommIEnReg     = 0x02
  DivlEnReg      = 0x03
  CommIrqReg     = 0x04
  DivIrqReg      = 0x05
  ErrorReg       = 0x06
  Status1Reg     = 0x07
  Status2Reg     = 0x08
  FIFODataReg    = 0x09
  FIFOLevelReg   = 0x0A
  WaterLevelReg  = 0x0B
  ControlReg     = 0x0C
  BitFramingReg  = 0x0D
  CollReg        = 0x0E
  Reserved01     = 0x0F
  
  Reserved10     = 0x10
  ModeReg        = 0x11
  TxModeReg      = 0x12
  RxModeReg      = 0x13
  TxControlReg   = 0x14
  TxASKReg       = 0x15
  TxSelReg       = 0x16
  RxSelReg       = 0x17
  RxThresholdReg = 0x18
  DemodReg       = 0x19
  Reserved11     = 0x1A
  Reserved12     = 0x1B
  MifareReg      = 0x1C
  Reserved13     = 0x1D
  Reserved14     = 0x1E
  SerialSpeedReg = 0x1F
  
  Reserved20        = 0x20  
  CRCResultRegM     = 0x21
  CRCResultRegL     = 0x22
  Reserved21        = 0x23
  ModWidthReg       = 0x24
  Reserved22        = 0x25
  RFCfgReg          = 0x26
  GsNReg            = 0x27
  CWGsPReg          = 0x28
  ModGsPReg         = 0x29
  TModeReg          = 0x2A
  TPrescalerReg     = 0x2B
  TReloadRegH       = 0x2C
  TReloadRegL       = 0x2D
  TCounterValueRegH = 0x2E
  TCounterValueRegL = 0x2F
  
  Reserved30      = 0x30
  TestSel1Reg     = 0x31
  TestSel2Reg     = 0x32
  TestPinEnReg    = 0x33
  TestPinValueReg = 0x34
  TestBusReg      = 0x35
  AutoTestReg     = 0x36
  VersionReg      = 0x37
  AnalogTestReg   = 0x38
  TestDAC1Reg     = 0x39
  TestDAC2Reg     = 0x3A
  TestADCReg      = 0x3B
  Reserved31      = 0x3C
  Reserved32      = 0x3D
  Reserved33      = 0x3E
  Reserved34      = 0x3F
    
  serNum = []
  
  def __init__(self):
    self.FF32_Init()
    self.MFRC522_Init()
    
  def MFRC522_Reset(self):
    self.Write_MFRC522(self.CommandReg, self.PCD_RESETPHASE)
  
  def Write_MFRC522(self,addr,val):
    # Grava no MFRC522. 
    bytes = bytearray([(addr<<1)&0x7E,val&0xFF])
    with pyff32.FF32() as ff32:
        try:
            ff32.writeSPIBus(bytes)
        except Exception as ex:
            print("Write_MFRC522: *** Erro (WriteSPIBus): " + ex.message)

  
  def Read_MFRC522(self,addr):
    # Lê 1 byte do MFRC522 registro passado como endereço. 
    bytes = bytearray([(addr<<1)&0x7E | 0x80])
    with pyff32.FF32() as ff32:
        try:
            bytes = ff32.readSPIBus(1, bytes)
        except Exception as ex:
            print("Read_MFRC522: *** Erro (ReadSPIBus): " + ex.message)
        
    return bytes[0]
  
  def SetBitMask(self, reg, mask):
    tmp = self.Read_MFRC522(reg)
    self.Write_MFRC522(reg, tmp | mask)
    
  def ClearBitMask(self, reg, mask):
    tmp = self.Read_MFRC522(reg);
    self.Write_MFRC522(reg, tmp & (~mask))
  
  def AntennaOn(self):
  # liga a antena se estiver desligada
    temp = self.Read_MFRC522(self.TxControlReg)
    if(~(temp & 0x03)):
        self.SetBitMask(self.TxControlReg, 0x03)
  
  def AntennaOff(self):
    # desliga a antena de acordo com o status anterior
    self.ClearBitMask(self.TxControlReg, 0x03)
	
  def FF32_Init(self):
    # pega a versão do chip
    with pyff32.FF32() as ff32:
        try:
            version = ff32.getChipInfo()
            if (version):
                print("FF32_Init: O chip é FF32, versão %d.%d" % version)
            else:
                print("FF32_Init: O chip não é FF32")
        except Exception as ex: 
            print("FF32_Init: *** Erro (getChipInfo): " + ex.message)
        # Pega o endereço do chip
        try:
            addr = ff32.getAddress()
            print ("FF32_Init: O endereço do chip é %d" % (addr))
        except Exception as ex: 
            print("FF32_Init: *** Erro (getAddress): " + ex.message)
        # Pega o fornecedor do chip
        try:
            vendor = ff32.getVendor()
            print("FF32_Init: O fornecedor da placa é %s" % (vendor))
        except Exception as ex: 
            print("FF32_Init: *** Erro (getVendor): " + ex.message)
        # Pega a placa
        try:
            product = ff32.getProduct()
            print("FF32_Init: O nome da placa é %s" % (product))
        except Exception as ex: 
            print("FF32_Init: *** Erro (getProduct): " + ex.message)
        # Pega o número de série
        try:
            serial = ff32.getSerialNumber()
            print("FF32_Init: O serial da placa é %s" % (serial))
        except Exception as ex: 
            print("FF32_Init: *** Erro (getSerialNumber): " + ex.message)
        # Configura os pins SPI
        try:
            ff32.setSPIPins(("A", 1), ("A", 2), ("A", 3), ("A", 4))
            print("FF32_Init: Os conectores SPI foram configurados como SS=A1,SCK=A2, MOSI=A3, MISO=A4")
        except Exception as ex:
            print("FF32_Init: *** Erro (SetSPIPins): " + ex.message)
	  
  def MFRC522_Init(self):
    # Uma vez que a comunicação SPI é estabelecida, o programa registra os valores iniciais
    self.MFRC522_Reset();                                       # reinicia o MFRD522
    if self.Read_MFRC522(self.VersionReg)==0x91:                # lê e checa a versão do RC522
        print("MFRC522_Init: RC522 versão 1.0 conectado")
    else:
        if self.Read_MFRC522(self.VersionReg)==0x92:
            print("MFRC522_Init: RC522 versão 2.0 conectado")
        else:
            print("MFRC522_Init: RC522 não detectado!")
            return
    self.Write_MFRC522(self.TModeReg, 0x8D)						# Programa o temporizador para 2kHz
    self.Write_MFRC522(self.TPrescalerReg, 0x3E)				#
    self.Write_MFRC522(self.TReloadRegL, 30)					# intervalo de 15,5 ms
    self.Write_MFRC522(self.TReloadRegH, 0)						#
    self.Write_MFRC522(self.TxASKReg, 0x40)						# Usa 100%  modulação ASK
    self.Write_MFRC522(self.ModeReg, 0x3D)
    self.AntennaOn()											# Liga a antena

  def MFRC522_Selftest(self):
    selfTestResultV1 = bytearray([0x00, 0xC6, 0x37, 0xD5, 0x32, 0xB7, 0x57, 0x5C,
                          0xC2, 0xD8, 0x7C, 0x4D, 0xD9, 0x70, 0xC7, 0x73,
                          0x10, 0xE6, 0xD2, 0xAA, 0x5E, 0xA1, 0x3E, 0x5A,
                          0x14, 0xAF, 0x30, 0x61, 0xC9, 0x70, 0xDB, 0x2E,
                          0x64, 0x22, 0x72, 0xB5, 0xBD, 0x65, 0xF4, 0xEC,
                          0x22, 0xBC, 0xD3, 0x72, 0x35, 0xCD, 0xAA, 0x41,
                          0x1F, 0xA7, 0xF3, 0x53, 0x14, 0xDE, 0x7E, 0x02,
                          0xD9, 0x0F, 0xB5, 0x5E, 0x25, 0x1D, 0x29, 0x79])
    selfTestResultV2 = bytearray([0x00, 0xEB, 0x66, 0xBA, 0x57, 0xBF, 0x23, 0x95,
                          0xD0, 0xE3, 0x0D, 0x3D, 0x27, 0x89, 0x5C, 0xDE,
                          0x9D, 0x3B, 0xA7, 0x00, 0x21, 0x5B, 0x89, 0x82,
                          0x51, 0x3A, 0xEB, 0x02, 0x0C, 0xA5, 0x00, 0x49,
                          0x7C, 0x84, 0x4D, 0xB3, 0xCC, 0xD2, 0x1B, 0x81,
                          0x5D, 0x48, 0x76, 0xD5, 0x71, 0x61, 0x21, 0xA9,
                          0x86, 0x96, 0x83, 0x38, 0xCF, 0x9D, 0x5B, 0x6D,
                          0xDC, 0x15, 0xBA, 0x3E, 0x7D, 0x95, 0x3B, 0x2F])
    if self.Read_MFRC522(self.VersionReg)==0x91:                # Read and check RC522 version number
        selfTestResult = selfTestResultV1
    else:
        if self.Read_MFRC522(self.VersionReg)==0x92:
            selfTestResult = selfTestResultV2
        else:
            return false
    self.MFRC522_Reset()
    self.Write_MFRC522(self.FIFODataReg, 0x00)
    self.Write_MFRC522(self.CommandReg, self.PCD_MEM)
    self.Write_MFRC522(self.AutoTestReg, 0x09)           # ativa o self test
    self.Write_MFRC522(self.FIFODataReg, 0x00)
    self.Write_MFRC522(self.CommandReg, self.PCD_CALC_CRC);   # inicia o self test

    # aguarda o selftest terminar.
    i = 0xFF
    while ((i != 0) & (0x04 & self.Read_MFRC522(self.DivIrqReg))):
        i -= 1
  
    # lê 64 bytes do FIFO e compara os dados esperados
    for i in range (0,64):
        if (self.Read_MFRC522(self.FIFODataReg) != selfTestResult[i]):
            print("MFRC522_Selftest: O teste falhou no byte {0:02}".format(i))
            return False

    return True

  def MFRC522_ToCard(self,command,sendData):
    backData = []
    backLen = 0
    status = self.MI_ERR
    irqEn = 0x00
    waitIRq = 0x00
    lastBits = None
    n = 0
    i = 0
    
    if command == self.PCD_AUTHENT:
        irqEn = 0x12
        waitIRq = 0x10
    if command == self.PCD_TRANSCEIVE:
        irqEn = 0x77
        waitIRq = 0x30
    
    self.Write_MFRC522(self.CommIEnReg, irqEn|0x80)
    self.ClearBitMask(self.CommIrqReg, 0x80)
    self.SetBitMask(self.FIFOLevelReg, 0x80)
    
    self.Write_MFRC522(self.CommandReg, self.PCD_IDLE) 
    
    # grava sendData no FIFO
    while(i<len(sendData)):
        self.Write_MFRC522(self.FIFODataReg, sendData[i])
        i += 1
    
    self.Write_MFRC522(self.CommandReg, command)
    
    # inicia a transmissao de dados  
    if command == self.PCD_TRANSCEIVE:
        self.SetBitMask(self.BitFramingReg, 0x80)
    
    i = 10
    while True:
        n = self.Read_MFRC522(self.CommIrqReg)
        time.sleep(0.1)
        i -= 1
        if ~((i!=0) and ~(n&0x01) and ~(n&waitIRq)):
            break
            
    # para a execução de dados
    self.ClearBitMask(self.BitFramingReg, 0x80)
    
    # um cartão foi detectado antes da contagem regressiva ler FIFO
    if i != 0:
        if (self.Read_MFRC522(self.ErrorReg) & 0x1B)==0x00:
            status = self.MI_OK

            if n & irqEn & 0x01:
                status = self.MI_NOTAGERR
      
            if command == self.PCD_TRANSCEIVE:
                n = self.Read_MFRC522(self.FIFOLevelReg)
                lastBits = self.Read_MFRC522(self.ControlReg) & 0x07
                if lastBits != 0:
                    backLen = (n-1)*8 + lastBits
                else:
                    backLen = n*8
          
            if n == 0:
                n = 1
            if n > self.MAX_LEN:
                n = self.MAX_LEN
    
            i = 0
            while i<n:
                backData.append(self.Read_MFRC522(self.FIFODataReg))
                i += 1
        else:
            status = self.MI_ERR

    return (status,backData,backLen)

  def MFRC522_Request(self, reqMode):
    status = None
    backBits = None
    TagType = []
    
    # TxLastBits set to 0b111: 
    self.Write_MFRC522(self.BitFramingReg, 0x07)
    
    TagType.append(reqMode);
    (status,backData,backBits) = self.MFRC522_ToCard(self.PCD_TRANSCEIVE, TagType)
  
    if ((status != self.MI_OK) | (backBits != 0x10)):
      status = self.MI_ERR
      
    return (status,backBits)
    
  def MFRC522_Anticoll(self):
    backData = []
    serNumCheck = 0
    serNum = []
  
    self.Write_MFRC522(self.BitFramingReg, 0x00)
    
    serNum.append(self.PICC_ANTICOLL)
    serNum.append(0x20)
    
    (status,backData,backBits) = self.MFRC522_ToCard(self.PCD_TRANSCEIVE,serNum)
    
    if(status == self.MI_OK):
        i = 0
        if len(backData)==5:
            while i<4:
                serNumCheck = serNumCheck ^ backData[i]
                i += 1
            if serNumCheck != backData[i]:
                status = self.MI_ERR
        else:
            status = self.MI_ERR
  
    return (status,backData)  

 
  def CalulateCRC(self, pIndata):
    self.ClearBitMask(self.DivIrqReg, 0x04)
    self.SetBitMask(self.FIFOLevelReg, 0x80);
    i = 0
    while i<len(pIndata):
        self.Write_MFRC522(self.FIFODataReg, pIndata[i])
        i += 1
    self.Write_MFRC522(self.CommandReg, self.PCD_CALC_CRC)
    i = 0xFF
    while True:
        n = self.Read_MFRC522(self.DivIrqReg)
        i -= 1
        if not ((i != 0) and not (n&0x04)):
            break
    pOutData = []
    pOutData.append(self.Read_MFRC522(self.CRCResultRegL))
    pOutData.append(self.Read_MFRC522(self.CRCResultRegM))
    return pOutData
  
  def MFRC522_SelectTag(self, serNum):
    backData = []
    buf = []
    buf.append(self.PICC_SElECTTAG)
    buf.append(0x70)
    i = 0
    while i<5:
        buf.append(serNum[i])
        i += 1
    pOut = self.CalulateCRC(buf)
    buf.append(pOut[0])
    buf.append(pOut[1])
    (status, backData, backLen) = self.MFRC522_ToCard(self.PCD_TRANSCEIVE, buf)
    
    if (status == self.MI_OK) and (backLen == 0x18):
        print("MFRC522_SelectTag: Tamanho: " + str(backData[0]))
        return  backData[0]
    else:
        return 0
  
  def MFRC522_Auth(self, authMode, BlockAddr, Sectorkey, serNum):
    buff = []
    buff.append(authMode)
    buff.append(BlockAddr)
    i = 0
    while(i < len(Sectorkey)):
        buff.append(Sectorkey[i])
        i += 1
    i = 0
    while(i < len(serNum)):
        buff.append(serNum[i])
        i += 1
    (status, backData, backLen) = self.MFRC522_ToCard(self.PCD_AUTHENT,buff)
    if not(status == self.MI_OK):
        print("MFRC522_Auth: Erro ao autenticar! Status retornado ",status)
    if not (self.Read_MFRC522(self.Status2Reg) & 0x08) != 0:
        print("MFRC522_Auth: Erro ao autenticar(status2reg & 0x08) != 0")

    return status 

 
#---------------- inicio do programa principal -------------------#  
do_selftest = False
print("Main: Inicializando...")
MIFAREReader = FF32Mifare()

if do_selftest:
    if MIFAREReader.MFRC522_Selftest():
        print("Main: Selftest correto...")
    else:
        print("Main: Selftest falhou...")  

while True:
    (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)
    if status == MIFAREReader.MI_OK:
        print("Main: Cartão detectado")
        (status,backData) = MIFAREReader.MFRC522_Anticoll()
        if status == MIFAREReader.MI_OK:
            print("Main: Cartão UID: "+str(backData[0])+","+str(backData[1])+","+str(backData[2])+","+str(backData[3])+","+str(backData[4]))
            if backData==([100,25,206,171,24]):
                with pyff32.FF32() as ff32:
                    try:
                        ff32.setDigitalOutput(("B", 1), 0)
                    except Exception as ex: 
                        print("*** Erro (setDigitalOutput): " + ex.message)
                    time.sleep(0.3)
                    try:
                        ff32.setDigitalOutput(("B", 1), 1)
                    except Exception as ex: 
                        print("*** Erro (setDigitalOutput): " + ex.message)
            else:
                 with pyff32.FF32() as ff32:
                    try:
                        ff32.setDigitalOutput(("B", 1), 0)
                    except Exception as ex: 
                        print("*** Erro (setDigitalOutput): " + ex.message)
                    time.sleep(0.6)
                    try:
                        ff32.setDigitalOutput(("B", 1), 1)
                    except Exception as ex: 
                        print("*** Erro (setDigitalOutput): " + ex.message)
                        


  

 
 