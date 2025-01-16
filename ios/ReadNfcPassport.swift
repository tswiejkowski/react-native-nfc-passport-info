import Foundation
import CoreNFC
import NFCPassportReader
import React
import Combine

final class SettingsStore: NSObject, ObservableObject {

    private enum Keys {
        static let captureLog = "captureLog"
        static let logLevel = "logLevel"
        static let useNewVerification = "useNewVerification"
        static let savePassportOnScan = "savePassportOnScan"
        static let passportNumber = "passportNumber"
        static let dateOfBirth = "dateOfBirth"
        static let dateOfExpiry = "dateOfExpiry"
        
        static let allVals = [captureLog, logLevel, useNewVerification, passportNumber, dateOfBirth, dateOfExpiry]
    }
    
    private let cancellable: Cancellable
    private let defaults: UserDefaults
    
    let objectWillChange = PassthroughSubject<Void, Never>()
    
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        

        defaults.register(defaults: [
            Keys.captureLog: true,
            Keys.logLevel: 2,
            Keys.useNewVerification: true,
            Keys.savePassportOnScan: false,
            Keys.passportNumber: "",
            Keys.dateOfBirth: Date().timeIntervalSince1970,
            Keys.dateOfExpiry: Date().timeIntervalSince1970,
        ])
        
        cancellable = NotificationCenter.default
            .publisher(for: UserDefaults.didChangeNotification)
            .map { _ in () }
            .subscribe(objectWillChange)
    }
    
    func reset() {
        if let bundleID = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundleID)
        }
    }
    
    var shouldCaptureLogs: Bool {
        set { defaults.set(newValue, forKey: Keys.captureLog) }
        get { defaults.bool(forKey: Keys.captureLog) }
    }
    
   /* var logLevel: LogLevel {
        get {
            return LogLevel(rawValue:defaults.integer(forKey: Keys.logLevel)) ?? .info
        }
        set {
            defaults.set(newValue.rawValue, forKey: Keys.logLevel)
        }
    }*/
    
    var useNewVerificationMethod: Bool {
        set { defaults.set(newValue, forKey: Keys.useNewVerification) }
        get { defaults.bool(forKey: Keys.useNewVerification) }
    }
    
    var savePassportOnScan: Bool {
        set { defaults.set(newValue, forKey: Keys.savePassportOnScan) }
        get { defaults.bool(forKey: Keys.savePassportOnScan) }
    }
    
    var passportNumber: String {
        set { defaults.set(newValue, forKey: Keys.passportNumber) }
        get { defaults.string(forKey: Keys.passportNumber) ?? "" }
    }
    
    var dateOfBirth: Date {
        set {
            defaults.set(newValue.timeIntervalSince1970, forKey: Keys.dateOfBirth)
        }
        get {
            let d = Date(timeIntervalSince1970: defaults.double(forKey: Keys.dateOfBirth))
            return d
        }
    }
    
    var dateOfExpiry: Date {
        set {
            defaults.set(newValue.timeIntervalSince1970, forKey: Keys.dateOfExpiry) }
        get {
            let d = Date(timeIntervalSince1970: defaults.double(forKey: Keys.dateOfExpiry))
            return d
        }
    }
    
    @Published var passport : NFCPassportModel?
}

@available(iOS 15, *)
@objc(ReadNfcPassport)
class ReadNfcPassport: NSObject {

  private let passportReader: Any
  private let settings = SettingsStore()
    private static let logger = Logger(
            subsystem: Bundle.main.bundleIdentifier!,
            category: String(describing: ReadNfcPassport.self)
    );
  
  override init() {
    guard #available(iOS 13, *) else {
      passportReader = NSNull()
      return;
    }
      passportReader = PassportReader()
  }
    
    private func convertImageToBase64String (img: UIImage?) -> String {
        return img != nil ? ( img!.jpegData(compressionQuality: 1)?.base64EncodedString() ?? "") : ""
    }
  
  @objc
  static func requiresMainQueueSetup() -> Bool {
    return true
  }
  
  @objc
  func constantsToExport() -> [AnyHashable : Any]! {
    guard #available(iOS 13, *) else {
      return ["isSupported": false]
    }

    if NSClassFromString("NFCNDEFReaderSession") == nil {
      return ["isSupported": false]
    }
    
    return ["isSupported": NFCNDEFReaderSession.readingAvailable]
  }
  
  func handleProgress(percentualProgress: Int) -> String {
     let p = (percentualProgress/20)
     let full = String(repeating: "🟢 ", count: p)
     let empty = String(repeating: "⚪️ ", count: 6 - p)
     return "\(full)\(empty)"
  }
        
    @objc(scanPassport:withResolver:withRejecter:)
    func scanPassport(options: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        
        guard let mrzKey = options.value(forKey: "mrz") as? String else {
                   resolve(["error": "Please provide a valid MRZ"])
                   return
               }
        
        Task {
                  let customMessageHandler : (NFCViewDisplayMessage)->String? = { (displayMessage) in
                    switch displayMessage {
                            case .requestPresentPassport:
                                let message = customMessages["requestPresentPassport"] as? String ?? "Hold your iPhone near an NFC enabled passport.";
                                return message
                            case .authenticatingWithPassport(let progress):
                                let message = customMessages["authenticatingWithPassport"] as? String ?? "Authenticating with passport.....";
                                let progressString = self.handleProgress(percentualProgress: progress)
                                return "\(message)\n\n\(progressString)"
                            case .readingDataGroupProgress(let dataGroup, let progress):
                                let message = customMessages["readingDataGroupProgress"] as? String ?? "Reading passport.....";
                                let progressString = self.handleProgress(percentualProgress: progress)
                                return "\(message)\n\n\(progressString)"
                            case .error(let tagError):
                                let message = customMessages["error"] as? String ?? "Failed to read Passport NFC";
                                let errorKey = tagError.errorDescription ?? "UnknownError"
                                return "\(message) (\(errorKey))"
                            case .successfulRead:
                                let message = customMessages["successfulRead"] as? String ?? "Passport read successfully";
                                return message
                            case .activeAuthentication:
                                let message = customMessages["activeAuthentication"] as? String ?? "activeAuthentication";
                                return message
                            }
                    }
            
            // Set the masterListURL on the Passport Reader to allow auto passport verification
            let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem")!
            (passportReader as! PassportReader).setMasterListURL( masterListURL )
                   
            // Set whether to use the new Passive Authentication verification method (default true) or the old OpenSSL CMS verifiction
            (passportReader as! PassportReader).passiveAuthenticationUsesOpenSSL = !settings.useNewVerificationMethod
            
            do {
                let passport = try await (passportReader as! PassportReader).readPassport( mrzKey: mrzKey, customDisplayMessage:customMessageHandler)
 
                DispatchQueue.main.async {
                    let photo = passport.passportImage
                    let photoBase64 = "data:image/png;base64," + self.convertImageToBase64String(img: photo)
                    var result: [String: Any] = [
                        "dateOfExpiry": passport.documentExpiryDate,
                        "passportMRZ": passport.passportMRZ,
                        "personalNumber": passport.personalNumber,
                        "dateOfBirth": passport.dateOfBirth,
                        "firstName" : passport.firstName,
                        "lastName" : passport.lastName,
                        "gender" : passport.gender,
                        "nationality" : passport.nationality,
                        "documentNumber": passport.documentNumber,
                        "passportCorrectlySigned":passport.passportCorrectlySigned,
                        "activeAuthenticationPassed":passport.activeAuthenticationPassed,
                        "documentSigningCertificateVerified": passport.documentSigningCertificateVerified,
                        "passportDataNotTampered": passport.passportDataNotTampered,
                        "photo" : [
                          "base64": photoBase64,
                          "width": (photo?.size.width ?? 100) * (photo?.scale ?? 1),
                          "height": (photo?.size.height ?? 100) * (photo?.scale ?? 1)
                      ]
                    ]
                    resolve(result)
                }
                
            } catch {
                reject("READ_PASSWORD_ERROR", error.localizedDescription, error)
            }
        }
                

    }
           
  }

