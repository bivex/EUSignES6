import { Utils } from "./euutils.js";
import { EUSignCP, setEUSignCPModuleInitialized } from "./euscpm.js";
import {
  EU_MAKE_PKEY_PFX_CONTAINER_PARAMETER,
  EU_CERT_KEY_TYPE_DSTU4145,
  EU_CERT_KEY_TYPE_RSA,
  EU_CERT_KEY_TYPE_ECDSA,
  EU_ERROR_CERT_NOT_FOUND,
  EU_ERROR_NOT_SUPPORTED,
  EU_WARNING_END_OF_ENUM,
  EU_SUBJECT_TYPE_END_USER,
  EU_KEY_USAGE_DIGITAL_SIGNATURE,
  UA_OID_EXT_KEY_USAGE_STAMP,
  EndUserCertificate, 
} from "./euscpm.js";
import { } from "./euscp.js";
export {euSignFactory}

class EUSignCPFactory {
  constructor() {
    this.URL_GET_CERTIFICATES =
      "/signdata/CACertificates.p7b?version=1.0.19";
    this.URL_CAS = "/signdata/CAs.json?version=1.0.19";
    this.URL_XML_HTTP_PROXY_SERVICE =
      "https://testsite.cna.ua/signdata/ProxyHandler.php";

    this.CertsLocalStorageName = "Certificates";
    this.CRLsLocalStorageName = "CRLs";
    this.PrivateKeyNameSessionStorageName = "PrivateKeyName";
    this.PrivateKeySessionStorageName = "PrivateKey";
    this.PrivateKeyPasswordSessionStorageName = "PrivateKeyPassword";
    this.PrivateKeyCertificatesSessionStorageName = "PrivateKeyCertificates";
    this.PrivateKeyCertificatesChainSessionStorageName =
      "PrivateKeyCertificatesChain";
    this.CACertificatesSessionStorageName = "CACertificates";
    this.CAServerIndexSessionStorageName = "CAServerIndex";

    //this.recepientsCertsIssuers" : null,
    //this.recepientsCertsSerials" : null,
        console.log("servers clerar");
    (this.CAsServers = null),
      (this.offline = false),
      (this.useCMP = false),
      (this.loadPKCertsFromFile = false), //не исп
      (this.privateKeyCerts = null), //не исп
      (this.CAServerIndex = -1),
      (this.defCAServerIndexJKS = null),
      (this.defCAServerIndexZS2 = null),
      (this.CAServerAutoDetected = true),
      (this.pkReaded = false),
      (this.pkFileObject = null),
      (this.pkFileName = null),
      (this.pkFileData = null),
      (this.pkFilePassword = null),
      (this.pkFileDataArray = null),
      (this.pkFileItemIndex = -1),
      (this.lastError = null),
      (this.onChangeCAs = null),
      (this.onChangePrivateKey = null),
      (this.onerror = null);
  }
  initialize() {
    setStatus("ініціалізація");
    var pThis = this;

    var _onSuccess = function () {
      try {
        euSign.Initialize();
        euSign.SetJavaStringCompliant(true);
        euSign.SetCharset("UTF-16LE");

        euSign.SetRuntimeParameter(EU_MAKE_PKEY_PFX_CONTAINER_PARAMETER, true);

        if (euSign.DoesNeedSetSettings()) {
          pThis.setDefaultSettings();

          if (utils.IsStorageSupported()) {
            //pThis.loadCertsAndCRLsFromLocalStorage();
          } else {
            /*document.getElementById(
              'SelectedCertsList').innerHTML = 
                "Локальне сховище не підтримується";
            document.getElementById(
              'SelectedCRLsList').innerHTML = 
                "Локальне сховище не підтримується";*/
          }
        }

        pThis.loadCertsFromServer();
        //pThis.setCASettings(0);

        //this.setSelectPKCertificatesEvents();

        /*if (utils.IsSessionStorageSupported()) {
          setTimeout( function() {
              this.readPrivateKeyAsStoredFile();
            }, 10);
        }*/

        //this.updateCertList();

        setStatus("");
      } catch (e) {
        setStatus("Не ініціалізовано");
        pThis.errorHandler(e);
        //alert(e);
      }
    };

    var _onError = function (e) {
      setStatus("Не ініціалізовано");
      pThis.errorHandler(
        "Виникла помилка при завантаженні криптографічної бібліотеки",
        e
      );
    };

    this.loadCAsSettings(_onSuccess, _onError);
  }

  isReady() {
    return this.CAsServers && this.CAsServers.length > 0;
  }

  errorHandler(msg, e) {
    this.lastError = msg + (e ? "(" + e + ")" : "");
    if (this.onerror) this.onerror(this.lastError);
  }

  loadCAsSettings(onSuccess, onError) {
    var pThis = this;

    var _onSuccess = function (casResponse) {
      try {
        var servers = JSON.parse(casResponse.replace(/\\'/g, "'"));

        /*var select = document.getElementById("CAsServersSelect");
        for (var i = 0; i < servers.length; i++){
          var option = document.createElement("option");
          option.text = servers[i].title// issuerCNs[0];
          select.add(option);
        }

        var option = document.createElement("option");
        option.text = "інший";
        select.add(option);

        select.onchange = function() {
          pThis.setCASettings(select.selectedIndex);
        };*/
        for(var i=0; i<servers.length; ++i){
          if( !('title' in servers[i] ) )
            servers[i].title = servers[i].issuerCNs[0];
          servers[i].index = i;
        }
        pThis.CAsServers = servers;
        console.log("servers loaded");
        pThis.defCAServerIndexJKS = null;
        pThis.defCAServerIndexZS2 = null;
        for (let i = 0; i < servers.length; ++i) {
          if (servers[i].codeEDRPOU == "36865753")
            pThis.defCAServerIndexZS2 = i;
          else if (servers[i].codeEDRPOU == "14360570")
            pThis.defCAServerIndexJKS = i;
        }

        if (pThis.onChangeCAs) pThis.onChangeCAs();

        onSuccess();
      } catch (e) {
        onError(e);
      }
    };

    euSign.LoadDataFromServer(this.URL_CAS, _onSuccess, onError, false);
  }
  /* не понял необходимости
	loadCertsAndCRLsFromLocalStorage: function() {
		try {
			var files = euSignTest.loadFilesFromLocalStorage(
				euSignTest.CertsLocalStorageName, 
				function(fileName, fileData) {
						if (fileName.indexOf(".cer") >= 0)
							euSign.SaveCertificate(fileData);
						else if (fileName.indexOf(".p7b") >= 0)
							euSign.SaveCertificates(fileData);
					});
			if (files != null && files.length > 0)
				euSignTest.setItemsToList('SelectedCertsList', files);
			else {
				document.getElementById('SelectedCertsList').innerHTML = 
					"Сертифікати відсутні в локальному сховищі";
			}
		} catch (e) {
			document.getElementById('SelectedCertsList').innerHTML = 
				"Виникла помилка при завантаженні сертифікатів " + 
				"з локального сховища";
		}
		
		try {
			var files = euSignTest.loadFilesFromLocalStorage(
				euSignTest.CRLsLocalStorageName, 
				function(fileName, fileData) {
						if (fileName.indexOf(".crl") >= 0) {
							try {
								euSign.SaveCRL(true, fileData);
							} catch (e) {
								euSign.SaveCRL(false, fileData);
							}
						}
					});
			if (files != null && files.length > 0)
				euSignTest.setItemsToList('SelectedCRLsList', files);
			else {
				document.getElementById('SelectedCRLsList').innerHTML = 
					"СВС відсутні в локальному сховищі";
			}
		} catch (e) {
			document.getElementById('SelectedCRLsList').innerHTML = 
				"Виникла помилка при завантаженні СВС з локального сховища";
		}
	},*/
  loadCertsFromServer() {
    var pThis = this;
    var certificates = utils.GetSessionStorageItem(
      this.CACertificatesSessionStorageName,
      true,
      false
    );
    if (certificates != null) {
      try {
        euSign.SaveCertificates(certificates);
        //this.updateCertList();
        return;
      } catch (e) {
        this.errorHandler(
          "Виникла помилка при імпорті " +
            "завантажених з сервера сертифікатів " +
            "до файлового сховища",
          e
        );
      }
    }

    var _onSuccess = function (certificates) {
      try {
        euSign.SaveCertificates(certificates);
        utils.SetSessionStorageItem(
          pThis.CACertificatesSessionStorageName,
          certificates,
          false
        );
        //pThis.updateCertList();
      } catch (e) {
        pThis.errorHandler(
          "Виникла помилка при імпорті " +
            "завантажених з сервера сертифікатів " +
            "до файлового сховища",
          e
        );
      }
    };

    var _onFail = function (errorCode) {
      console.log(
        "Виникла помилка при завантаженні сертифікатів з сервера. " +
          "(HTTP статус " +
          errorCode +
          ")"
      );
    };

    utils.GetDataFromServerAsync(
      this.URL_GET_CERTIFICATES,
      _onSuccess,
      _onFail,
      true
    );
  }

  setDefaultSettings() {
    try {
      euSign.SetXMLHTTPProxyService(this.URL_XML_HTTP_PROXY_SERVICE);

      var settings = euSign.CreateFileStoreSettings();
      settings.SetPath("/certificates");
      settings.SetSaveLoadedCerts(true);
      euSign.SetFileStoreSettings(settings);

      settings = euSign.CreateProxySettings();
      euSign.SetProxySettings(settings);

      settings = euSign.CreateTSPSettings();
      euSign.SetTSPSettings(settings);

      settings = euSign.CreateOCSPSettings();
      euSign.SetOCSPSettings(settings);

      settings = euSign.CreateCMPSettings();
      euSign.SetCMPSettings(settings);

      settings = euSign.CreateLDAPSettings();
      euSign.SetLDAPSettings(settings);

      settings = euSign.CreateOCSPAccessInfoModeSettings();
      settings.SetEnabled(true);
      euSign.SetOCSPAccessInfoModeSettings(settings);

      var CAs = this.CAsServers;
      settings = euSign.CreateOCSPAccessInfoSettings();
      for (var i = 0; i < CAs.length; i++) {
        settings.SetAddress(CAs[i].ocspAccessPointAddress);
        settings.SetPort(CAs[i].ocspAccessPointPort);

        for (var j = 0; j < CAs[i].issuerCNs.length; j++) {
          settings.SetIssuerCN(CAs[i].issuerCNs[j]);
          euSign.SetOCSPAccessInfoSettings(settings);
        }
      }
    } catch (e) {
      this.errorHandler("Виникла помилка при встановленні налашувань", e);
    }
  }

  setCASettings(caIndex) {
    try {
      var caServer =
        caIndex < this.CAsServers.length ? this.CAsServers[caIndex] : null;
      var offline = caServer == null || caServer.address == "" ? true : false;
      var useCMP = !offline && caServer.cmpAddress != "";
      var loadPKCertsFromFile =
        caServer == null || (!useCMP && !caServer.certsInKey);

      //this.CAServer = caServer;
      this.CAServerIndex = caIndex;
      this.offline = offline;
      this.useCMP = useCMP;
      this.loadPKCertsFromFile = loadPKCertsFromFile;

      /*document.getElementById('ChoosePKFileText').innerHTML = 
            	"Оберіть файл з особистим ключем " + 
            	"(зазвичай з ім'ям Key-6.dat) та вкажіть пароль захисту";
            if (loadPKCertsFromFile) {
            	document.getElementById('ChoosePKFileText').innerHTML +=
            		", а також оберіть сертифікат(и)";
            }*/

      var settings;

      //document.getElementById('PKCertsSelectZone').hidden =
      //	loadPKCertsFromFile ? '' : 'hidden';
      //this.clearPrivateKeyCertificatesList();

      settings = euSign.CreateTSPSettings();
      if (!offline) {
        settings.SetGetStamps(true);
        if (caServer.tspAddress != "") {
          settings.SetAddress(caServer.tspAddress);
          settings.SetPort(caServer.tspAddressPort);
        } else {
          settings.SetAddress("acskidd.gov.ua");
          settings.SetPort("80");
        }
      }
      euSign.SetTSPSettings(settings);

      settings = euSign.CreateOCSPSettings();
      if (!offline) {
        settings.SetUseOCSP(true);
        settings.SetBeforeStore(true);
        settings.SetAddress(caServer.ocspAccessPointAddress);
        settings.SetPort("80");
      }
      euSign.SetOCSPSettings(settings);

      settings = euSign.CreateCMPSettings();
      settings.SetUseCMP(useCMP);
      if (useCMP) {
        settings.SetAddress(caServer.cmpAddress);
        settings.SetPort("80");
      }
      euSign.SetCMPSettings(settings);

      settings = euSign.CreateLDAPSettings();
      euSign.SetLDAPSettings(settings);
    } catch (e) {
      this.errorHandler("Виникла помилка при встановленні налашувань: ", e);
    }
  }

  //-----------------------------------------------------------------------------
  /*updateCertList: function() {
    	var certSubjType = SubjectCertTypes[
    		document.getElementById('CertTypeSelect').selectedIndex];
    	var certKeyType = CertKeyTypes[
    		document.getElementById('CertKeyTypeSelect').selectedIndex];
    	var keyUsage = KeyUsages[
    		document.getElementById('KeyUsageSelect').selectedIndex];

    	try {
    		var index = 0;
    		var cert;
    		var certs = [];

    		while (true) {
    			cert = euSign.EnumCertificatesEx(
    				certSubjType.type, certSubjType.subtype,
    				certKeyType, keyUsage, index);
    			if (cert == null)
    				break;
    			
    			certs.push(cert);
    			index++;
    		};
    		
    		if (certs.length == 0) {
    			document.getElementById('StorageCertList').innerHTML = 
    				"Сертифікати відсутні";
    			return;
    		}
    		
    		var _makeCertField = function(name, value, addNewLine) {
    			return name + ': ' + 
    				value  + 
    				(addNewLine ? '<br>' : '');
    		}
    		
    		var certInfos = [];

    		for (var i = 0; i < certs.length; i++) {
    			var certInfoStr = '';
    			var certInfo = certs[i].GetInfoEx();
    			var publicKeyType = '';
    			switch (certInfo.GetPublicKeyType()) {
    				case EU_CERT_KEY_TYPE_DSTU4145:
    					publicKeyType += 'ДСТУ-4145';
    					break;
    				case EU_CERT_KEY_TYPE_RSA:
    					publicKeyType += 'RSA';
    					break;
    				case EU_CERT_KEY_TYPE_ECDSA:
    					publicKeyType += 'ECDSA';
    					break;
    				default:
    					publicKeyType = 'Невизначено';
    					break;
    			}
    			
    			certInfoStr += _makeCertField('Власник', certInfo.GetSubjCN(), true);
    			certInfoStr += _makeCertField('ЦСК', certInfo.GetIssuerCN(), true);
    			certInfoStr += _makeCertField('Серійний номер', certInfo.GetSerial(), true);
    			certInfoStr += _makeCertField('Тип', publicKeyType, true);
    			certInfoStr += _makeCertField('Призначення', certInfo.GetKeyUsage(), false);
    			
    			certInfos.push(certInfoStr);
    		}
    		
    		euSignTest.setItemsToList(
    			'StorageCertList', certInfos);
    	} catch (e) {
    		this.errorHandler("Виникла помилка при " + 
    			"отриманні сертифікатів з файлового сховища", e);
    	}
    },*/
  //-----------------------------------------------------------------------------
  getCAServer() {
    return this.CAServerIndex >= 0 &&
      this.CAServerIndex < this.CAsServers.length
      ? this.CAsServers[this.CAServerIndex]
      : null;
  }

  loadCAServer() {
    var index = utils.GetSessionStorageItem(
      this.CAServerIndexSessionStorageName,
      false,
      false
    );
    if (index != null) {
      this.setCASettings(parseInt(index));
    }
  }

  storeCAServer() {
    return utils.SetSessionStorageItem(
      this.CAServerIndexSessionStorageName,
      this.CAServerIndex.toString(),
      false
    );
  }

  removeCAServer() {
    utils.RemoveSessionStorageItem(this.CAServerIndexSessionStorageName);
  }
  //-----------------------------------------------------------------------------
  storePrivateKey(keyName, key, password, certificates) {
    if (
      !utils.SetSessionStorageItem(
        this.PrivateKeyNameSessionStorageName,
        keyName,
        false
      ) ||
      !utils.SetSessionStorageItem(
        this.PrivateKeySessionStorageName,
        key,
        false
      ) ||
      !utils.SetSessionStorageItem(
        this.PrivateKeyPasswordSessionStorageName,
        password,
        true
      ) ||
      !this.storeCAServer()
    ) {
      return false;
    }

    if (Array.isArray(certificates)) {
      if (
        !utils.SetSessionStorageItems(
          this.PrivateKeyCertificatesSessionStorageName,
          certificates,
          false
        )
      ) {
        return false;
      }
    } else {
      if (
        !utils.SetSessionStorageItem(
          this.PrivateKeyCertificatesChainSessionStorageName,
          certificates,
          false
        )
      ) {
        return false;
      }
    }

    return true;
  }

  removeStoredPrivateKey() {
    utils.RemoveSessionStorageItem(this.PrivateKeyNameSessionStorageName);
    utils.RemoveSessionStorageItem(this.PrivateKeySessionStorageName);
    utils.RemoveSessionStorageItem(this.PrivateKeyPasswordSessionStorageName);
    utils.RemoveSessionStorageItem(
      this.PrivateKeyCertificatesChainSessionStorageName
    );
    utils.RemoveSessionStorageItem(
      this.PrivateKeyCertificatesSessionStorageName
    );

    this.removeCAServer();
  }

  getPrivateKeyCertificatesByCMP(key, password, onSuccess, onError) {
    try {
      var cmpAddress = this.getCAServer().cmpAddress + ":80";
      var keyInfo = euSign.GetKeyInfoBinary(key, password);
      onSuccess(euSign.GetCertificatesByKeyInfo(keyInfo, [cmpAddress]));
    } catch (e) {
      onError(e);
    }
  }

  getPrivateKeyCertificates(key, password, fromCache, onSuccess, onError) {
    var certificates;

    var caServer = this.getCAServer();
    if (caServer && caServer.certsInKey) {
      onSuccess([]);
      return;
    }

    if (fromCache) {
      if (this.useCMP) {
        certificates = utils.GetSessionStorageItem(
          this.PrivateKeyCertificatesChainSessionStorageName,
          true,
          false
        );
      } else if (this.loadPKCertsFromFile) {
        certificates = utils.GetSessionStorageItems(
          this.PrivateKeyCertificatesSessionStorageName,
          true,
          false
        );
      }

      onSuccess(certificates);
    } else if (this.useCMP) {
      this.getPrivateKeyCertificatesByCMP(key, password, onSuccess, onError);
    } else if (this.loadPKCertsFromFile) {
      var _onSuccess = function (files) {
        var certificates = [];
        for (var i = 0; i < files.length; i++) {
          certificates.push(files[i].data);
        }

        onSuccess(certificates);
      };

      euSign.ReadFiles(this.privateKeyCerts, _onSuccess, onError);
    }
  }

  readPrivateKey(keyName, key, password, certificates, fromCache) {
    var pThis = this;
    this.pkReaded = false;
    var _onError = function (e) {
      setStatus("");
        
      if (fromCache) {
        pThis.removeStoredPrivateKey();
        pThis.privateKeyReaded(false);
      } else {
        pThis.errorHandler(e);
      }

      /*if (e.GetErrorCode != null && 
            	e.GetErrorCode() == EU_ERROR_CERT_NOT_FOUND) {
            	this.mainMenuItemClicked(
            		document.getElementById('MainPageMenuCertsAndCRLs'),
            		'MainPageMenuCertsAndCRLsPage');
            }*/
    };

    if (certificates == null) {
      var _onGetCertificates = function (certs) {
        if (certs == null) {
          _onError(euSign.MakeError(EU_ERROR_CERT_NOT_FOUND));
          return;
        }

        pThis.readPrivateKey(keyName, key, password, certs, fromCache);
      };

      pThis.getPrivateKeyCertificates(
        key,
        password,
        fromCache,
        _onGetCertificates,
        _onError
      );
      return;
    }

    try {
      if (Array.isArray(certificates)) {
        for (var i = 0; i < certificates.length; i++) {
          euSign.SaveCertificate(certificates[i]);
        }
      } else {
        euSign.SaveCertificates(certificates);
      }

      euSign.ReadPrivateKeyBinary(key, password);

      if (!fromCache && utils.IsSessionStorageSupported()) {
        if (!this.storePrivateKey(keyName, key, password, certificates)) {
          this.removeStoredPrivateKey();
        }
      }

      this.privateKeyReaded(true);

      //this.updateCertList();

      //if (!fromCache)
      //	this.showOwnerInfo();
    } catch (e) {
      _onError(e);
    }
  }

  readPrivateKeyAsImage(onSuccess) {
    var image = new Image();
    image.onload = function () {
      try {
        var qr = new QRCodeDecode();

        var canvas = document.createElement("canvas");
        var context = canvas.getContext("2d");

        canvas.width = image.width;
        canvas.height = image.height;

        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        var imagedata = context.getImageData(0, 0, canvas.width, canvas.height);
        var decoded = qr.decodeImageData(
          imagedata,
          canvas.width,
          canvas.height
        );
        var arr = [];
        for (var i = 0; i < decoded.length; i++)
          arr.push(decoded.charCodeAt(i));
        pkFileName = file.name;
        pkFileData = arr;
        pkFileDataArray = null;
        onSuccess();
      } catch (e) {
        this.errorHandler(e);
      }
    };

    image.src = utils.CreateObjectURL(this.pkFileObject);
  }

  readPrivateKeyAsStoredFile() {
    var keyName = utils.GetSessionStorageItem(
      this.PrivateKeyNameSessionStorageName,
      false,
      false
    );
    var key = utils.GetSessionStorageItem(
      this.PrivateKeySessionStorageName,
      true,
      false
    );
    var password = utils.GetSessionStorageItem(
      this.PrivateKeyPasswordSessionStorageName,
      false,
      true
    );
    if (keyName == null || key == null || password == null) return;

    this.loadCAServer();

    setStatus("зчитування ключа");
    this.pkFileObject = null;
    this.pkFileName = keyName;
    this.pkFileData = key;
    this.pkFilePassword = password;
    var _readPK = function () {
      this.readPrivateKey(keyName, key, password, null, true);
    };
    setTimeout(_readPK, 10);

    return;
  }

  setPrivateKeyFile(file) {
    var pThis = this;
    var changed = this.pkFileObject != file;
    if (changed) {
      this.pkFileObject = file;
      this.pkFileData = null;
      this.updatePrivateKeyDataFromFileObject(function () {
        if (pThis.onChangePrivateKeyFile) pThis.onChangePrivateKeyFile();
      });
    }
  }

  readPrivateKeyButtonClick() {
    //тут считаем что пароль уже есть - пытаемся прочитать
    var pThis = this;
    var certificatesFiles = this.privateKeyCerts;

    var _onError = function (e) {
      setStatus("");
      pThis.errorHandler(e);
    };

    var _onSuccess = function (keyName, key) {
      pThis.readPrivateKey(
        keyName,
        new Uint8Array(key),
        this.pkFilePassword,
        null,
        false
      );
    };

    try {
      setStatus("зчитування ключа");

      if (this.pkFileName === null) {
        this.removeStoredPrivateKey();
        this.pkFileObject = null;
        this.pkFileData = null;
        this.pkFileDataArray = null;
        euSign.ResetPrivateKey();
        this.privateKeyReaded(false);
      } else {
        if (!this.pkFileName || !this.pkFileData) {
          _onError(
            "Виникла помилка при зчитуванні особистого ключа. " +
              "Опис помилки: файл з особистим ключем не обрано"
          );
          return;
        }

        if (!this.pkFilePassword) {
          _onError(
            "Виникла помилка при зчитуванні особистого ключа. " +
              "Опис помилки: не вказано пароль доступу до особистого ключа"
          );
          return;
        }

        if (
          this.loadPKCertsFromFile &&
          (certificatesFiles == null || certificatesFiles.length <= 0)
        ) {
          _onError(
            "Виникла помилка при зчитуванні особистого ключа. " +
              "Опис помилки: не обрано жодного сертифіката відкритого ключа"
          );
          return;
        }

        this.readPrivateKey(
          this.pkFileName,
          this.pkFileData,
          this.pkFilePassword,
          null,
          false
        );
      }
    } catch (e) {
      _onError(e);
    }
  }

  GetJKSPrivateKeys(jks, onSuccess) {
    var keys = [];
    try {
      var keyIndex = 0;
      while (true) {
        var alias = euSign.EnumJKSPrivateKeys(jks, keyIndex);
        var key = euSign.GetJKSPrivateKey(jks, alias);
        var certs = [];
        var certsnoinfo = [];
        var stamp = false;
        for (var i = 0; i < key.GetCertificatesCount(); i++) {
          var cert = key.GetCertificate(i);
          var infoEx = euSign.ParseCertificateEx(cert);
          if (infoEx.GetSubjType() != EU_SUBJECT_TYPE_END_USER) continue;

          if (
            infoEx.GetPublicKeyType() == EU_CERT_KEY_TYPE_DSTU4145 &&
            (infoEx.GetKeyUsageType() & EU_KEY_USAGE_DIGITAL_SIGNATURE) ==
              EU_KEY_USAGE_DIGITAL_SIGNATURE
          ) {
            stamp =
              infoEx.GetExtKeyUsages().indexOf(UA_OID_EXT_KEY_USAGE_STAMP) > -1;
          }

          certsnoinfo.push(cert);
          var euCert = new EndUserCertificate(infoEx, cert);
          certs.push(euCert.GetTransferableObject());
        }

        var jksKey = {
          index: keyIndex,
          title: (certs[0]?.infoEx?.subjCN).toString() + ' (' + alias.toString() + ')',
          alias: alias,
          privateKey: key.GetPrivateKey(),
          certificates: certs,
          certs: certsnoinfo,
          digitalStamp: stamp,
        };
        keys.push(jksKey);

        keyIndex++;
      }
    } catch (e) {
      if (!e.GetErrorCode || e.GetErrorCode() != EU_WARNING_END_OF_ENUM) {
        setStatus("");
        this.errorHandler(e);
      }
    }
    onSuccess(keys);
  }

  GetFileExtension(fileName) {
    return fileName
      ? fileName
          .substring(fileName.lastIndexOf(".") + 1, fileName.length)
          .toLowerCase()
      : null;
  }

  updatePrivateKeyDataFromFileObject(onSuccess) {
    //обновить pkFileData, pkFileDataArray
    var pThis = this;
    var selected = !!this.pkFileObject;
    pThis.pkFileDataArray = null;
    pThis.pkFileData = null;
    if (!selected) {
      pThis.pkFileName = null;
      if (this.CAServerAutoDetected) {
        this.CAServerIndex = null;
        //this.CAServer = null;
      }
      onSuccess();
      return;
    }
    var fileName = this.pkFileObject.name;
    var fileExt = this.GetFileExtension(fileName);

    var _onSuccessGetJKS = function (jksInfos) {
      if (jksInfos.length == 0) {
        pThis.errorHandler(
          "Виникла помилка при зчитуванні особистого ключа. " +
            "Опис помилки: файл з особистим ключем пошкоджено - перелік сертифікатів порожній"
        );
        return;
      }
      pThis.pkFileDataArray = jksInfos;
      //jksInfos[].certificates
      //jksInfos[].alias
      onSuccess();
    };

    var _onFileReadJKS = function (fileData) {
      pThis.pkFileData = fileData.data;
      pThis.GetJKSPrivateKeys(fileData.data, _onSuccessGetJKS);
    };
    var _onFileReadDef = function (fileData) {
      pThis.pkFileData = fileData.data;
      onSuccess();
    };

    this.pkFileName = fileName;
    if (selected) {
      if (utils.IsFileImage(this.pkFileObject)) {
        this.readPrivateKeyAsImage(_onSuccess);
      } else {
        if (fileExt == "jks") {
          if (this.CAServerAutoDetected) {
            this.CAServerIndex = this.defCAServerIndexJKS;
          }
          euSign.ReadFile(
            this.pkFileObject,
            _onFileReadJKS,
            pThis.errorHandler
          );
        } else {
          if (fileExt == "zs2" && this.CAServerAutoDetected)
            this.CAServerIndex = this.defCAServerIndexZS2;
          euSign.ReadFile(
            this.pkFileObject,
            _onFileReadDef,
            pThis.errorHandler
          );
        }
      }
    }
  }

  //-----------------------------------------------------------------------------
  signData(data, isInternalSign, isAddCert, signAlg /*def, hash, rsa*/) {
    /*var data = document.getElementById('DataToSignTextEdit').value + "";
        var isInternalSign = 
        	document.getElementById("InternalSignCheckbox").checked;
        var isAddCert = 
        	document.getElementById("AddCertToInternalSignCheckbox").checked;
        var isSignHash = 
        	document.getElementById("SignHashCheckbox").checked;
        var signedDataText = document.getElementById("SignedDataText"); 
        var dsAlgType = parseInt(document.getElementById("DSAlgTypeSelect").value)
		
        signedDataText.value = "";*/

    setStatus("підпис данних");
    var sign = "";
    try {
      if (signAlg != "rsa") {
        if (isInternalSign) {
          sign = euSign.SignDataInternal(isAddCert, data, true);
        } else {
          if ((signAlg == "hash")) {
            var hash = euSign.HashData(data);
            sign = euSign.SignHash(hash, true);
          } else {
            sign = euSign.SignData(data, true);
          }
        }
      } else {
        sign = euSign.SignDataRSA(data, isAddCert, !isInternalSign, true);
      }
      setStatus("");
    } catch (e) {
      setStatus("");
      this.errorHandler(e);
    }
    return sign;
  }

  /*verifyData: function () {
    	var data = document.getElementById('DataToSignTextEdit').value + "";
    	var signedData = document.getElementById('SignedDataText').value;
    	var isInternalSign = 
    		document.getElementById("InternalSignCheckbox").checked;
    	var isSignHash = 
    		document.getElementById("SignHashCheckbox").checked;
    	var isGetSignerInfo = 
    		document.getElementById("GetSignInfoCheckbox").checked;
    	var verifiedDataText = document.getElementById("VerifiedDataText");
    	var dsAlgType = parseInt(document.getElementById("DSAlgTypeSelect").value)
    	verifiedDataText.value = "";

    	var _verifyDataFunction = function() {
    		try {
    			var info = "";
    			if (isInternalSign) {
    				info = euSign.VerifyDataInternal(signedData);
    			} else {
    				if (isSignHash && dsAlgType == 1) {
    					var hash = euSign.HashData(data);
    					info = euSign.VerifyHash(hash, signedData);
    				} else {
    					info = euSign.VerifyData(data, signedData);
    				}
    			}
    		
    			var message = "Підпис успішно перевірено";
    		
    			if (isGetSignerInfo) {
    				var ownerInfo = info.GetOwnerInfo();
    				var timeInfo = info.GetTimeInfo();

    				message += "\n";
    				message += "Підписувач: " + ownerInfo.GetSubjCN() + "\n" + 
    							"ЦСК: " + ownerInfo.GetIssuerCN() + "\n" + 
    							"Серійний номер: " + ownerInfo.GetSerial() + "\n";
    				if (timeInfo.IsTimeAvail()) {
    					message += (timeInfo.IsTimeStamp() ? 
    						"Мітка часу (від даних):" : "Час підпису: ") + timeInfo.GetTime();
    				} else {
    					message += "Час підпису відсутній";
    				}

    				if (timeInfo.IsSignTimeStampAvail()) {
    					message += "\nМітка часу (від підпису):" + timeInfo.GetSignTimeStamp();
    				}
    			}
    		
    			if (isInternalSign) {
    				message += "\n";
    				verifiedDataText.value = euSign.ArrayToString(info.GetData());
    				message += "Підписані дані: " + verifiedDataText.value + "\n";
    			}
    		
    			setStatus('');
    			alert(message);
    		} catch (e) {
    			setStatus('');
    			this.errorHandler(e);
    		}
    	}

    	setStatus('перевірка підпису даних');
    	setTimeout(_verifyDataFunction, 10);
    },*/
  //-----------------------------------------------------------------------------
  /*signFile: function() {
    	var file = document.getElementById('FileToSign').files[0];
    	
    	if (file.size > Module.MAX_DATA_SIZE) {
    		this.errorHandler("Розмір файлу для піпису занадто великий. Оберіть файл меншого розміру");
    		return;
    	}
    	
    	var fileReader = new FileReader();

    	fileReader.onloadend  = (function(fileName) {
    		return function(evt) {
    			if (evt.target.readyState != FileReader.DONE)
    				return;

    			var isInternalSign = 
    				document.getElementById("InternalSignCheckbox").checked;
    			var isAddCert = document.getElementById(
    				"AddCertToInternalSignCheckbox").checked;
    			var dsAlgType = parseInt(
    				document.getElementById("DSAlgTypeSelect").value);

    			var data = new Uint8Array(evt.target.result);

    			try {
    				var sign;

    				if (dsAlgType == 1) {
    					if (isInternalSign)
    						sign = euSign.SignDataInternal(isAddCert, data, false);
    					else
    						sign = euSign.SignData(data, false);
    				} else {
    					sign = euSign.SignDataRSA(data, isAddCert, 
    						!isInternalSign, false);
    				}

    				saveFile(fileName + ".p7s", sign);

    				setStatus('');
    				alert("Файл успішно підписано");
    			} catch (e) {
    				setStatus('');
    				this.errorHandler(e);
    			}
    		};
    	})(file.name);

    	setStatus('підпис файлу');
    	fileReader.readAsArrayBuffer(file);
    },*/
  //-----------------------------------------------------------------------------
  getOwnCertificateInfo(keyType, keyUsage) {
    try {
      var index = 0;
      while (true) {
        var info = euSign.EnumOwnCertificates(index);
        if (info == null) return null;

        if (
          info.GetPublicKeyType() == keyType &&
          (info.GetKeyUsageType() & keyUsage) == keyUsage
        ) {
          return info;
        }

        index++;
      }
    } catch (e) {
      this.errorHandler(e);
    }

    return null;
  }
  //-----------------------------------------------------------------------------
  loadFilesFromLocalStorage(localStorageFolder, loadFunc) {
    if (!utils.IsStorageSupported()) euSign.RaiseError(EU_ERROR_NOT_SUPPORTED);

    if (utils.IsFolderExists(localStorageFolder)) {
      var files = utils.GetFiles(localStorageFolder);
      for (var i = 0; i < files.length; i++) {
        var file = utils.ReadFile(localStorageFolder, files[i]);
        loadFunc(files[i], file);
      }
      return files;
    } else {
      utils.CreateFolder(localStorageFolder);
      return null;
    }
  }

  saveFileToModuleFileStorage(fileName, fileData) {
    var filesListName = null;
    try {
      var array = new Uint8Array(fileData);
      var folderName = null;

      if (fileName.indexOf(".cer") >= 0) {
        filesListName = "SelectedCertsList";
        euSign.SaveCertificate(array);
        folderName = this.CertsLocalStorageName;
      } else if (fileName.indexOf(".p7b") >= 0) {
        euSign.SaveCertificates(array);
        folderName = this.CertsLocalStorageName;
      } else if (fileName.indexOf(".crl") >= 0) {
        filesListName = "SelectedCRLsList";
        try {
          euSign.SaveCRL(true, array);
        } catch (e) {
          euSign.SaveCRL(false, array);
        }
        folderName = this.CRLsLocalStorageName;
      }

      if (folderName != null && utils.IsStorageSupported()) {
        utils.WriteFile(folderName, fileName, array);
      }
    } catch (e) {
      this.errorHandler(e);
    }

    //this.updateCertList();
  }

  isCertificateExtension(fileName) {
    if (fileName.indexOf(".cer") >= 0 || fileName.indexOf(".p7b") >= 0)
      return true;
    return false;
  }

  isCRLExtension(fileName) {
    if (fileName.indexOf(".crl") >= 0) return true;
    return false;
  }
  //-----------------------------------------------------------------------------
  privateKeyReaded(isReaded) {
    this.pkReaded = isReaded;
  }
  /*setSelectPKCertificatesEvents: function() {
        	document.getElementById('ChoosePKCertsInput').addEventListener(
        		'change',  function(evt) {
        			if (evt.target.files.length <= 0) {
        				euSignTest.clearPrivateKeyCertificatesList();
        			} else {
        				euSignTest.privateKeyCerts = evt.target.files;
        				euSignTest.setFileItemsToList("SelectedPKCertsList", 
        					evt.target.files);
        			}
        		}, false);
        	
        	document.getElementById('PKCertsDropZone').addEventListener(
        		'dragover', function(evt) {
        			evt.stopPropagation();
        			evt.preventDefault();
        			evt.dataTransfer.dropEffect = 'copy';
        		}, false);

        	document.getElementById('PKCertsDropZone').addEventListener(
        		'drop', function(evt) {
        			evt.stopPropagation();
        			evt.preventDefault();

        			if (evt.dataTransfer.files.length <= 0) {
        				euSignTest.clearPrivateKeyCertificatesList();
        			} else {
        				euSignTest.privateKeyCerts = evt.dataTransfer.files;
        				euSignTest.setFileItemsToList("SelectedPKCertsList", 
        					evt.dataTransfer.files);
        			}
        		}, false);
        },
        clearPrivateKeyCertificatesList: function() {
        	euSignTest.privateKeyCerts = null;
        	document.getElementById('ChoosePKCertsInput').value = null;
        	document.getElementById('SelectedPKCertsList').innerHTML = 
        		"Сертифікати відкритого ключа не обрано" + '<br>';
        },
        setItemsToList: function(listId, items) {
        	var output = [];
        	for (var i = 0, item; item = items[i]; i++) {
        		output.push('<li><strong>', item, '</strong></li>');
        	}

        	document.getElementById(listId).innerHTML = 
        		'<ul>' + output.join('') + '</ul>';
        },
        setFileItemsToList: function(listId, items) {
        	var output = [];
        	for (var i = 0, item; item = items[i]; i++) {
        		output.push('<li><strong>', item.name, '</strong></li>');
        	}

        	document.getElementById(listId).innerHTML = 
        		'<ul>' + output.join('') + '</ul>';
        }*/
}

//=============================================================================

var euSignFactory = new EUSignCPFactory();
var euSign = new EUSignCP();
var utils = new Utils(euSign);

setEUSignCPModuleInitialized(function (isInitialized) {
  if (isInitialized) euSignFactory.initialize();
  else alert("Криптографічну бібліотеку не ініціалізовано");
});

//=============================================================================

function setPointerEvents(element, enable) {
  element.style.pointerEvents = enable ? "auto" : "none";
}

function setStatus(message) {
  if (message != "") message = "(" + message + "...)";
  var el = document.getElementById("euOperationStatus")
  if(el)
    el.innerHTML = message;
}

function saveFile(fileName, array) {
  var blob = new Blob([array], { type: "application/octet-stream" });
  saveAs(blob, fileName);
}

/*function pageLoaded() {
	document.getElementById('CertsAndCRLsFiles').addEventListener(
		'change', euSignTest.chooseCertsAndCRLs, false);
	document.getElementById('PKeyFileInput').addEventListener(
		'change', euSignTest.selectPrivateKeyFile, false);
	document.getElementById('RecipientsCertsFiles').addEventListener(
		'change', euSignTest.chooseRecepientsCertificates, false);
	document.getElementById('FileToSign').addEventListener(
		'change', euSignTest.chooseFileToSign, false);
	document.getElementById('FileToVerify').addEventListener(
		'change', euSignTest.chooseFileToVerify, false);
	document.getElementById('FileWithSign').addEventListener(
		'change', euSignTest.chooseFileToVerify, false);
	document.getElementById('EnvelopFiles').addEventListener(
		'change', euSignTest.chooseEnvelopFile, false);

	var appendMaxFileSizeLimit = function(textLabelId) {
		var str = document.getElementById(textLabelId).innerHTML;
		str = str.substring(0, str.length - 1) + 
			" (не більше " + EU_MAX_DATA_SIZE_MB + " МБ):";
		document.getElementById(textLabelId).innerHTML = str;
	}

	appendMaxFileSizeLimit('ChooseFileForSignTextLabel');
	appendMaxFileSizeLimit('ChooseFileForVerifyTextLabel');
	appendMaxFileSizeLimit('ChooseFileForEnvelopTextLabel');
}*/

//=============================================================================
