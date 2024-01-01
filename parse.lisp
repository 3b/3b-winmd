#++(ql:quickload '(3b-winmd))
(in-package #:3b-winmd)

(defun octet-vector (&rest r)
  (coerce r '(simple-array (unsigned-byte 8) 1)))

;; https://github.com/microsoft/win32metadata
;; https://learn.microsoft.com/en-us/uwp/winrt-cref/winmd-files
;; https://www.nuget.org/packages/Microsoft.Windows.SDK.Win32Metadata/
;; https://ecma-international.org/publications-and-standards/standards/ecma-335/

;; todo: parse PE files instead of just assuming it starts here
(defvar *offset* #x250)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *tables*
    #(MODULE TYPE-REF TYPE-DEF NIL FIELD NIL METHOD-DEF NIL PARAM
      INTERFACE-IMPL MEMBER-REF CONSTANT CUSTOM-ATTRIBUTE FIELD-MARSHAL
      DECL-SECURITY CLASS-LAYOUT FIELD-LAYOUT STAND-ALONE-SIG EVENT-MAP
      NIL EVENT PROPERTY-MAP NIL PROPERTY METHOD-SEMANTICS METHOD-IMPL
      MODULE-REF TYPE-SPEC IMPL-MAP FIELD-RVA NIL NIL ASSEMBLY
      ASSEMBLY-PROCESSOR ASSEMBLY-OS ASSEMBLY-REF ASSEMBLY-REF-PROCESSOR
      ASSEMBLY-REF-OS FILE EXPORTED-TYPE MANIFEST-RESOURCE NESTED-CLASS
      GENERIC-PARAM METHOD-SPEC GENERIC-PARAM-CONSTRAINT NIL NIL NIL NIL
      NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)))

;; table name (symbol) -> index (filled in by define-table)
(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *table-index*
    (a:alist-hash-table (loop for a from 0 for b across *tables*
                              when b collect (cons b a)))))



(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-zstring (s:io-string)
    ())

  (defmethod s:octet-size ((type io-zstring))
    '*)

  (defmethod s:read-form ((backend s:io-backend) (type io-zstring))
    `(let ((octet (coerce (loop for i = ,(s:read-form backend 's:uint8)
                                until (zerop i)
                                collect i)
                          '(simple-array (unsigned-byte 8) 1))))
       (babel:octets-to-string octet :encoding ,(s:encoding type)))))

(s:define-io-type-parser zstring (&optional (encoding :utf-8))
  (make-instance 'io-zstring :element-count '* :encoding encoding))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-pad-string (s:io-string)
    ())

  (defmethod s:read-form ((backend s:io-backend) (type io-pad-string))
    `(let ((octet (coerce (loop for i = ,(s:read-form backend 's:uint8)
                                until (zerop i)
                                collect i)
                          '(simple-array (unsigned-byte 8) 1))))
       #++
       (prog1 (babel:octets-to-string octet :encoding ,(s:encoding type))
         ,(s:seek-form backend '*)
         ,(s:seek-form backend `(* 4 (ceiling ,(s:index-form backend) 4))))
       (prog1 (babel:octets-to-string octet :encoding ,(s:encoding type))
         ,(s:seek-form backend '*)
         (loop until (zerop (mod ,(s:index-form backend) 4))
               collect ,(s:read-form backend 's:uint8))))))

(s:define-io-type-parser pad-string (&optional (encoding :ascii))
  (make-instance 'io-pad-string :element-count '* :encoding encoding))


;;; enums and flags
(defmacro enum (name type &body values)
  `(s:define-io-alias ,name ;; ii.23.1.1
       (enum ,type ,@values)))

;; can't use CASE directly because it errors on unknown values and we
;; need to be able to parse garbage
;;;;; actually can probably switch back to CASE, since these should
;;;;; not have garbage?
(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-enum (s:io-case)
    ())

  #++
  (defvar *base* nil) ;; debugging

  (defmethod s:read-form ((backend s:io-backend) (type io-enum))
    (let ((value (gensym "VALUE")))
      `(let ((,value ,(s:read-form backend (s:value-type type))))
         (cond ,@(loop for (test form) in (s:cases type)
                       collect (list (etypecase test
                                       (number `(= ,value ,test))
                                       (character `(char= ,value ,test))
                                       (string `(string= ,value ,test))
                                       (symbol `(eq ,value ',test))
                                       (vector `(equalp ,value ,test)))
                                     (if (constantp form)
                                         form
                                         (s:read-form backend form))))
               (T (break "unknown enum ~s @ ~x~% expected ~s"
                         ,value
                         nil #++(- (cffi:pointer-address s::pointer)
                                   *base*)
                             ',(mapcar 'car (s:cases type)))
                  ,value))))))

(s:define-io-type-parser enum (value-type &rest cases)
  (make-instance 'io-enum :value-type value-type :cases cases))

(defmacro flags (name type &body values)
  `(s::define-io-flags ,name ,type
     ,@values))

(enum assembly-hash-algorithm s:uint32 ;; ii.23.1.1
  (#x0000 :none)
  (#x8003 :reserved-md5)
  (#x8004 :sha1))

(flags assembly-flags s:uint32 ;; ii.23.1.2
  (#x0001 :public-key)
  (#x0100 :retargetable)
  (#x4000 :disable-jit-compile-optimizer)
  (#x8000 :enable-jit-compile-tracking))

;; limited to specific values (case-folded?) but ignoring for now
(s:define-io-alias culture string-index) ;; ii.23.1.3

(enum event-attributes s:uint16 ;; ii.23.1.4
  (#x0200 :special-name)
  (#x0400 :rt-special-name))

(flags field-attributes s:uint16 ;; ii.23.1.5
  ((logand #x0007) :field-access
   (#x0000 :compiler-controlled)
   (#x0001 :private)
   (#x0002 :fam-and-assem)
   (#x0003 :Assembly)
   (#x0004 :family)
   (#x0005 :fam-or-assem)
   (#x0006 :public))
  (#x0010 :static)
  (#x0020 :init-only)
  (#x0040 :literal)
  (#x0080 :not-serialized)
  (#x0200 :special-name)
  (#x2000 :pinvoke-impl)
  (#x0400 :rt-special-name)
  (#x1000 :has-field-marshal)
  (#x8000 :has-default)
  (#x0100 :has-field-rva))

(flags file-attributes s:uint32 ;; ii.23.1.6
  (#x0000 :contains-metadata)
  (#x0001 :contains-no-metadata))

(flags generic-param-attributes s:uint16 ;; ii.23.1.7
  ;; not sure if these are flags or enums in a bitfield?
  ((mask-field (byte 2 0)) :variance
   (#x0000 :none)
   (#x0001 :covariant)
   (#x0002 :contravariant))
  ;; not sure if these are supposed to be exclusive or if more than 1
  ;; can be set?
  ((mask-field (byte 3 2)) :special-constraint
   (#x0004 :reference-type-constraint)
   (#x0008 :not-nullable-value-type-constraint)
   (#x0010 :default-constructor-constraint)))

(flags p-invoke-attributes s:uint16 ;; ii.23.1.8
  (#x0001 :no-mangle)
  ((mask-field (byte 2 1)) :char-set
   (#x0000 :char-set-not-specified)
   (#x0002 :char-set-ansi)
   (#x0004 :char-set-unicode)
   (#x0006 :char-set-auto))
  (#x0040 :support-last-error)
  ((logand #x0700) :call-conv
   (#x0100 :platform-api)
   (#x0200 :cdecl)
   (#x0300 :stdcall)
   (#x0400 :thiscall)
   (#x0500 :fastcall)))

(flags manifest-resource-attributes s:uint32 ;; ii.23.1.9
  ((logand #x0007) :visibility
   (#x0001 :public)
   (#x0002 :private)))

(flags method-attributes s:uint16 ;; ii.23.1.10
  ((logand #x0007) :member-access
   (#x0000 :compiler-controlled)
   (#x0001 :private)
   (#x0002 :fam-and-assem)
   (#x0003 :Assembly)
   (#x0004 :family)
   (#x0005 :fam-or-assem)
   (#x0006 :public))
  (#x0010 :static)
  (#x0020 :final)
  (#x0040 :virtual)
  (#x0080 :hide-by-sig)
  ((logand #x0100) :vtable-layout ;; probably should just be a single flag?
   (#x0000 :reuse-slot)
   (#x0100 :new-slot))
  (#x0200 :strict)
  (#x0400 :abstract)
  (#x0800 :special-name)
  (#x2000 :pinvoke-impl)
  (#x0008 :unmanaged-export)
  (#x1000 :rt-special-name)
  (#x4000 :has-security)
  (#x8000 :require-sec-object))

(flags method-impl-attributes s:uint16
  ((logand #x0003) :code-type
   (#x0000 :il)
   (#x0001 :native)
   (#x0002 :optil)
   (#x0003 :runtime))
  ;; probably should just be the :unmanaged flag?
  ;; or add a (#x0000 :managed :mask #x0004) syntax?
  ((logand #x0004) :managed
   (#x0004 :unmanaged)
   (#x0000 :managed))
  (#x0010 :forward-ref)
  (#x0080 :Preserve-Sig) ;; Reserved: conforming implementations can ignore
  (#x1000 :Internal-Call) ;; Reserved: shall be zero in conforming implementations
  (#x0020 :Synchronized) ;; Method is single threaded through the body
  (#x0008 :No-Inlining)  ;; Method cannot be inlined
  (#xffff :Max-Method-Impl-Val) ;; Range check value
  (#x0040 :No-Optimization)) ;; Method will not be optimized when generating native code

(flags method-semantics-attributes s:uint16
  (#x0001 :Setter) ;; Setter for property
  (#x0002 :Getter) ;; Getter for property
  (#x0004 :Other)  ;; Other method for property or event
  (#x0008 :AddO-n) ;; AddOn method for event. This refers to the required add_ for events. (§22.13)
  (#x0010 :Remove-On) ;; RemoveOn method for event. . This refers to the required_ method for events. (§22.13)
  (#x0020 :Fire)) ;; Fire method for event. This refers to the optional raise_method for events. (§22.13)

(flags param-attributes s:uint16
  (#x0001 :In)                ;; Param is [In]
  (#x0002 :Out)               ;; Param is [out]
  (#x0010 :Optional)          ;; Param is optional
  (#x1000 :Has-Default)       ;; Param has default value
  (#x2000 :Has-Field-Marshal) ;; Param has FieldMarshal
  (#xcfe0 :Unused)) ;; Reserved: shall be zero in a conforming implementatiom

(flags property-attributes s:uint16
  (#x0200 :Special-Name) ;; Property is special
  (#x0400 :RT-Special-Name) ;; Runtime(metadata internal APIs) should check name encoding
  (#x1000 :Has-Default)     ;; Property has default
  (#xe9ff :Unused)) ;; Reserved: shall be zero in a conforming implementation

;; some values added from https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/metadata/cortypeattr-enumeration
(flags type-attributes s:uint32
;;; Visibility attributes
  ((logand #x00000007) :Visibility
   (#x00000000 :Not-Public)    ;; Class has no public scope
   (#x00000001 :Public)        ;; Class has public scope
   (#x00000002 :Nested-Public) ;; Class is nested with public visibility
   (#x00000003 :Nested-Private) ;; Class is nested with private visibility
   (#x00000004 :Nested-Family) ;; Class is nested with family visibility
   (#x00000005 :Nested-Assembly) ;; Class is nested with assembly visibility
   (#x00000006 :Nested-Fam-AND-Assem) ;; Class is nested with family and assembly visibility
   (#x00000007 :Nested-Fam-OR-Assem)) ;; Class is nested with family or assembly visibility
;;; Class layout attributes
  ((logand #x00000018) :Layout
   (#x00000000 :Auto-Layout)       ;; Class fields are auto-laid out
   (#x00000008 :Sequential-Layout) ;; Class fields are laid out sequentially
   (#x00000010 :Explicit-Layout))  ;; Layout is supplied explicitly
;;; Class semantics attributes
  ((logand #x00000020) :Class-Semantics
   (#x00000000 :Class)      ;; Type is a class
   (#x00000020 :Interface)) ;; Type is an interface
;;; Special semantics in addition to class semantics
  (#x00000080 :Abstract)           ;; Class is abstract
  (#x00000100 :Sealed)             ;; Class cannot be extended
  (#x00000400 :Special-Name)       ;; Class name is special
;;; Implementation Attributes
  (#x00001000 :Import)             ;; Class/Interface is imported
  (#x00002000 :Serializable)       ;; Reserved (Class is serializable)
  (#x00004000 :td-windows-runtime) ;; used in WinRT winmd files
;;; String formatting Attributes
  ((logand #x00030000) :String-Format
   ;; possibly should rename these so they are more obvious when
   ;; separate from mask name?
   (#x00000000 :Ansi-Class)    ;; LPSTR is interpreted as ANSI
   (#x00010000 :Unicode-Class) ;; LPSTR is interpreted as Unicode
   (#x00020000 :Auto-Class)    ;; LPSTR is interpreted automatically
   (#x00030000 :Custom-Format-Class)) ;; A non-standard encoding specified by CustomStringFormatMask
  ((logand #x00C00000) :Custom-String-Format) ;; The meaning of the values of these 2 bits is unspecified.
  ;; Class Initialization Attributes
  (#x00100000 :Before-Field-Init) ;; Initialize the class before first static field access
;;; Additional Flags
  (#x00000800 :RT-Special-Name) ;; CLI provides 'special' behavior, depending upon the name of the Type
  (#x00040000 :Has-Security)    ;; Type has security associate with it
  (#x00200000 :Is-Type-Forwarder)) ;; This ExportedType entry is a type forwarder

(enum element-type s:uint8
  (#x00 :END) ;; Marks end of a list
  (#x01 :VOID)
  (#x02 :BOOLEAN)
  (#x03 :CHAR)
  (#x04 :I1)
  (#x05 :U1)
  (#x06 :I2)
  (#x07 :U2)
  (#x08 :I4)
  (#x09 :U4)
  (#x0a :I8)
  (#x0b :U8)
  (#x0c :R4)
  (#x0d :R8)
  (#x0e :STRING)
  (#x0f :PTR)        ;; Followed by type
  (#x10 :BY-REF)     ;; Followed by type
  (#x11 :VALUE-TYPE) ;; Followed by TypeDef or TypeRef token
  (#x12 :CLASS)      ;; Followed by TypeDef or TypeRef token
  (#x13 :VAR) ;; Generic parameter in a generic type definition, represented as number (compressed unsigned integer)
  (#x14 :ARRAY) ;; type rank boundsCount bound1 … loCount lo1 …
  (#x15 :GENERIC-INST) ;; Generic type instantiation. Followed by type type-arg-count type-1 ... type-n
  (#x16 :TYPED-BY-REF)
  (#x18 :I)       ;;System.IntPtr
  (#x19 :U)       ;; System.UIntPtr
  (#x1b :FNPTR)   ;; Followed by full method signature
  (#x1c :OBJECT)  ;; System.Object
  (#x1d :SZARRAY) ;; Single-dim array with 0 lower bound
  (#x1e :MVAR) ;; Generic parameter in a generic method definition, represented as number (compressed unsigned integer)
  (#x1f :CMOD-REQD) ;; Required modifier : followed by a TypeDef or TypeRef token
  (#x20 :CMOD-OPT) ;; Optional modifier : followed by a TypeDef or TypeRef token
  (#x21 :INTERNAL) ;; Implemented within the CLI
  (#x40 :MODIFIER) ;; Or’d with following element types
  (#x41 :SENTINEL) ;; Sentinel for vararg method signature
  (#x45 :PINNED) ;; Denotes a local variable that points at a pinned object
  (#x50 :system.type) ;; Indicates an argument of type System.Type.
  (#x51 :custom/boxed-object) ;; Used in custom attributes to specify a boxed object (§II.23.3).
  (#x52 :reserved)            ;;Reserved
  (#x53 :custom/field) ;; Used in custom attributes to indicate a FIELD (§II.22.10, II.23.3).
  (#x54 :custom/property) ;; Used in custom attributes to indicate a PROPERTY (§II.22.10, II.23.3).
  (#x55 :custom/enum)) ;; Used in custom attributes to specify an enum (§II.23.3)

;;; needed to determine sizes of indices while parsing

;; store # of bytes used to store corresponding index type
(defparameter *heap-sizes* (a:alist-hash-table '((:string . 0)
                                                 (:guid . 0)
                                                 (:blob . 0)
                                                 (:us . 0))))

;; # of rows in corresponding tables
(declaim (type (simple-array (unsigned-byte 32) (64)) *table-sizes*))
(defparameter *table-sizes* (make-array 64 :element-type '(unsigned-byte 32)
                                           :initial-element 0))
(defun 2-byte-table-p (table-name)
  (< (aref *table-sizes* (gethash table-name *table-index* table-name))
     (expt 2 16)))

(defmacro with-sizes ((heap-sizes valid rows) &body body)
  `(let ((*heap-sizes* (make-hash-table))
         (*table-sizes* (make-array 64 :element-type '(unsigned-byte 32)
                                       :initial-element 0)))
     (format t "rows = ~s~%" ,rows)
     (setf (gethash :string *heap-sizes*)
           (if (logbitp 0 ,heap-sizes) 4 2))
     (setf (gethash :guid *heap-sizes*)
           (if (logbitp 1 ,heap-sizes) 4 2))
     (setf (gethash :blob *heap-sizes*)
           (if (logbitp 2 ,heap-sizes) 4 2))
     (setf (gethash :us *heap-sizes*)
           ;; spec doesn't mention this, is it always 2 or 4, or same
           ;; as one of the others?
           (if (logbitp 3 ,heap-sizes) 4 2))
     (loop with v = ,valid
           with sizes = (coerce ,rows 'list)
           for i below 64
           do (when (logbitp i v)
                (setf (aref *table-sizes* i) (pop sizes))))
     (format t "table sizes = ~s~%" *table-sizes*)
     ,@body))

;;; table index types
(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-index-type (s:io-type)
    ())

  (defmethod s:default-value ((type io-index-type))
    nil)
  (defmethod s:lisp-type ((type io-index-type))
    t)
  (defmethod s:octet-size ((type io-index-type))
    '*)
  (defmethod s:write-form ((backend s:io-backend) (type io-index-type)
                           value-variable)
    (declare (ignore type))
    `(progn
       (error "todo can't write ~s to ~s~%" ,value-variable 'io-index-type)
       ;; get rid of unused variable notes
       ,(s:write-form backend 's:uint32 value-variable))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-heap-index (io-index-type)
    ((heap :initarg :heap :reader heap)))

  (defmethod s:initargs append ((type io-heap-index))
    (list :heap (heap type)))
  (defmethod s:default-value ((type io-heap-index))
    nil)
  (defmethod s:read-form ((backend s:io-backend) (type io-heap-index))
    `(let ((index (ecase (gethash ,(heap type) *heap-sizes*)
                    (2 ,(s:read-form backend 's:uint16))
                    (4 ,(s:read-form backend 's:uint32)))))
       (if (zerop index)
           nil
           (make-instance 'heap-ref :heap ,(heap type) :index index))))

  (defmethod s:write-form ((backend s:io-backend) (type io-heap-index) v)
    `(error "can't write heap index yet ~s~%" ',v)))

(defvar *streams* nil)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass heap-ref ()
    ((heap :initarg :heap :reader heap)
     (index :initarg :index :Reader index))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass table-ref ()
    ((table :initarg :table :reader table)
     (index :initarg :index :Reader index))))

(s:define-io-type-parser string-index ()
  (make-instance 'io-heap-index :heap :string))

(s:define-io-type-parser guid-index ()
  (make-instance 'io-heap-index :heap :guid))

(s:define-io-type-parser blob-index ()
  (make-instance 'io-heap-index :heap :blob))

(s:define-io-type-parser us-index ()
  (make-instance 'io-heap-index :heap :us))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-table-index (io-index-type)
    ((table-id :initarg :table-id :reader table-id)))

  (defmethod s:initargs append ((type io-table-index))
    (list :table-id (table-id type)))

  (defmethod s:read-form ((backend s:io-backend) (type io-table-index))
    ;; todo: define table<->id mapping early to allow expanding to an
    ;; index here
    `(let ((id (gethash ',(table-id type) *table-index*)))
       (if (2-byte-table-p id)
           ;; store id . index to match composite (and simplify lookups)
           (make-instance 'table-ref :table id
                                     :index ,(s:read-form backend 's:uint16))
           (make-instance 'table-ref :table id
                                     :index ,(s:read-form backend 's:uint32))))))

(s:define-io-type-parser field-index () ;; /list
  (make-instance 'io-table-index :table-id 'field))

(s:define-io-type-parser param-index () ;; /list
  (make-instance 'io-table-index :table-id 'param))

(s:define-io-type-parser event-index () ;; /list
  (make-instance 'io-table-index :table-id 'event))

(s:define-io-type-parser property-index () ;; /list
  (make-instance 'io-table-index :table-id 'property))

(s:define-io-type-parser generic-param-index ()
  (make-instance 'io-table-index :table-id 'generic-param))

(s:define-io-type-parser method-def-index () ;; /list
  (make-instance 'io-table-index :table-id 'method-def))

(s:define-io-type-parser type-def-index ()
  (make-instance 'io-table-index :table-id 'type-def))

(s:define-io-type-parser module-ref-index ()
  (make-instance 'io-table-index :table-id 'module-ref))

(s:define-io-type-parser assembly-ref-index ()
  (make-instance 'io-table-index :table-id 'assembly-ref))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-composite-table-index (io-index-type)
    ((bits :initarg :bits :reader bits)
     (table-ids :initarg :table-ids :reader table-ids)))

  (defmethod s:initargs append ((type io-composite-table-index))
    (list :bits (bits type) :table-ids (table-ids type)))

  (defmethod s:read-form ((backend s:io-backend) (type io-composite-table-index))
    ;; read as a cons of (table-index table-row)
    `(let ((max-table (max ,@(loop
                               for (nil i) in  (table-ids type)
                               collect `(aref *table-sizes*
                                              (gethash ',i *table-index*))))))
       (let* ((tagged (if (<= max-table
                              ,(expt 2 (- 16 (bits type))))
                          ,(s:read-form backend 's:uint16)
                          ,(s:read-form backend 's:uint32)))
              (tag (ldb (byte ,(bits type) 0) tagged))
              ;; extra bits are 0 anyway even if we only read 16, so
              ;; just grab 32
              (row (ldb (byte 32 ,(bits type)) tagged)))
         (case tag
           ,@(loop for (tag type) in (table-ids type)
                   for table = `(gethash ',type *table-index* ',type)
                   collect `(,tag (make-instance 'table-ref :table ,table
                                                            :index row)))
           (otherwise (if (zerop row)
                          nil
                          (list :? tag row))))))))

(defmacro define-table-index (name bits &body tables)
  `(s:define-io-type-parser ,name ()
     (make-instance 'io-composite-table-index
                    :bits ',bits
                    :table-ids ',tables)))

(define-table-index type-def-or-ref 2
  (0 Type-Def)
  (1 Type-Ref)
  (2 Type-Spec))

(define-table-index has-constant 2
  (0 Field)
  (1 Param)
  (2 Property))

(define-table-index has-custom-attribute 5
  (0 Method-Def)     ;; 06
  (1 Field)          ;; 04
  (2 Type-Ref)       ;; 01
  (3 Type-Def)       ;; 02
  (4 Param)          ;;08
  (5 Interface-Impl) ;; 09
  (6 Member-Ref)     ;; 0a
  (7 Module)         ;; 00
  ;; (8 Permission) i assume it means DeclSecurtity table?
  (8 decl-security)
  (9 Property)                  ;; 17
  (10 Event)                    ;; 14
  (11 Stand-Alone-Sig)          ;; 11
  (12 Module-Ref)               ;; 1a
  (13 Type-Spec)                ;; 1b
  (14 Assembly)                 ;; 20
  (15 Assembly-Ref)             ;; 23
  (16 File)                     ;; 26
  (17 Exported-Type)            ;; 27
  (18 Manifest-Resource)        ;; 28
  (19 Generic-Param)            ;; 2a
  (20 Generic-Param-Constraint) ;; 2c
  (21 Method-Spec))             ;; 2b

(define-table-index has-field-marshal 1
  (0 Field)
  (1 Param))

(define-table-index has-decl-security 2
  (0 Type-Def)
  (1 Method-Def)
  (2 Assembly))

(define-table-index member-ref-parent 3
  (0 Type-Def)
  (1 Type-Ref)
  (2 Module-Ref)
  (3 Method-Def)
  (4 Type-Spec))

(define-table-index has-semantics 1
  (0 Event)
  (1 Property))

(define-table-index method-def-or-ref 1
  (0 method-def)
  (1 method-ref))

(define-table-index member-forwarded 1
  (0 field)
  (1 method-def))

(define-table-index implementation 2
  (0 file)
  (1 assembly-ref)
  (2 exported-type))

(define-table-index custom-attribute-type 3
  ;; 0,1,4 not used
  (2 method-def)
  (3 member-ref))

(define-table-index resolution-scope 2
  (0 Module)
  (1 Module-Ref)
  (2 Assembly-Ref)
  (3 Type-Ref))

(define-table-index type-or-method-def 1
  (0 type-def)
  (1 method-def))
(s:define-io-structure foo
  (s s:uint8))

;;; tables

(defmacro define-table (name index &body slots)
  `(progn
     (s:define-io-structure ,name
       ,@ (loop for s in slots
                for c = (copy-list s)
                do (remf (cddr c) :list)
                collect c))
     (eval-when (:compile-toplevel :load-toplevel :execute)
       (setf (gethash ',name *table-index*) ,index))
     (defmethod update-refs ((row ,name) header next-row)
       ,@(loop for (sn st . keys) in slots
               for list = (getf keys :list)
               for iot = (s:parse-io-type st)
               for accessor = (s::intern* name '- sn)
               for access = `(,accessor row)
               when (typep iot '(or io-heap-index
                                 io-table-index
                                 io-composite-table-index))
                 collect (if list
                             (let* ((table-name (ecase st
                                                  (field-index 'field)
                                                  (method-def-index 'method-def)
                                                  (param-index 'param)
                                                  (event-index 'event)
                                                  (property-index 'property)))
                                    (table-id (gethash table-name
                                                       *table-index*)))
                               `(if ,access
                                    (let* ((table (aref (~stream-tables
                                                         (header-~ header))
                                                        ,table-id))
                                           (end (if next-row
                                                    (1-
                                                     (index (,accessor next-row)))
                                                    (length table)))
                                           (ref ,access))
                                      (unless (= (table ref) ,table-id)
                                        (break "got list ref for wrong table?~% got ~s expected ~s~%" ,table-id (car ref)))
                                      (setf ,access
                                            (subseq table (1- (index ref)) end)))))
                             `(setf ,access
                                    (update-table-ref ,access header
                                                      row ',accessor)))))
     (assert (eql (aref *tables* ,index) ',name))))


(define-table module #x00 ;; ii.22.30
  (generation s:uint16)
  (name string-index)
  (mvid guid-index)
  (enc-id guid-index)
  (enc-base-id guid-index))

(define-table type-ref #x01 ;; ii.22.38
  (resolution-scope resolution-scope)
  (type-name string-index)
  (type-namespace string-index))

(define-table type-def #x02 ;; ii.22.37
  (flags type-attributes)
  (type-name string-index)
  (type-namespace string-index)
  (extends type-def-or-ref)
  (field-list field-index :list t)        ;;/list
  (method-list method-def-index :list t)) ;;/list

;; 0x03 = x?

(define-table field #x04
  (flags field-attributes) ;; s:uint16 ii.23.1.5
  (name string-index)
  (signature blob-index))

;; 0x05 = x?

(define-table method-def #x06 ;; ii.22.26
  (rva s:uint32)
  (impl-flags method-impl-attributes)
  (flags method-attributes)
  (name string-index)
  (signature blob-index)
  (param-list param-index :list t)) ;;/list

;; 0x07 = x

(define-table param #x08 ;; ii.22.33
  (flags param-attributes)
  (sequence s:uint16)
  (name string-index))

(define-table interface-impl #x09 ;; ii.22.23
  (class type-def-index)
  (interface type-def-or-ref))

(define-table member-ref #x0a ;; ii.22.25
  (class member-ref-parent)
  (name string-index)
  (signature blob-index))

(define-table constant #x0b ;; ii.22.9
  (type element-type)
  (pad s:uint8) ;; 9
  (parent has-constant)
  (value blob-index))

(define-table custom-attribute #x0c ;; ii.22.10
  (parent has-custom-attribute)
  (type custom-attribute-type)
  (value blob-index))

(define-table field-marshal #x0d ;; ii.22.17
  (parent has-field-marshal)
  (native-type blob-index))

(define-table decl-security #x0e ;; ii.22.11
  (action s:uint16)
  (parent has-decl-security)
  (permission-set blob-index))

(define-table class-layout #x0f ;; ii.22.8
  (packing-size s:uint16)
  (class-size s:uint32)
  (parent type-def-index))

(define-table field-layout #x10 ;; ii.22.16
  (offset s:uint32)
  (field field-index))

(define-table stand-alone-sig #x11 ;; ii.22.36
  (signature blob-index))

(define-table event-map #x12 ;; ii.22.12
  (parent type-def-index)
  (event-list event-index :list t)) ;;/list

;; #x13 = x

(define-table event #x14 ;; ii.22.13
  (event-flags event-attributes)
  (name string-index)
  (event-type type-def-or-ref))

(define-table property-map #x15 ;; ii.22.35
  (parent type-def-index)
  (property-list property-index :list t)) ;;/list

;; #x16 = x

(define-table property #x17 ;; ii.22.34
  (flags property-attributes)
  (name string-index)
  (type blob-index))

(define-table method-semantics #x18 ;; ii.22.28
  (semantics method-semantics-attributes)
  (method method-def-index)
  (association has-semantics))

(define-table method-impl #x19 ;; ii.22.27
  (class type-def-index)
  (method-body method-def-or-ref)
  (method-declaration method-def-or-ref))

(define-table module-ref #x1a ;; ii.22.31
  (name string-index))

(define-table type-spec #x1b ;; ii.22.39
  (signature blob-index)) ;; ii.23.2.14

(define-table impl-map #x1c           ;; ii.22.22
  (mapping-flags p-invoke-attributes) ;; s:uint16 23.1.8
  (member-forwarded member-forwarded)
  (import-name string-index)
  (import-scope module-ref-index))

(define-table field-rva #x1d ;;ii.22.18
  (rva s:uint32)
  (field field-index))

;; #x1e, #x1f = x
(define-table assembly #x20             ; ii.22.2
  (hash-alg-id assembly-hash-algorithm) ;; s:uint32 ii.23.1.1
  (major-version s:uint16)
  (minor-version s:uint16)
  (build-number s:uint16)
  (revision-number s:uint16)
  (flags assembly-flags) ;; s:uint32 ii.23.1.2
  (public-key blob-index)
  (name string-index)
  (culture string-index))

(define-table assembly-processor #x21 ;; ii.22.4
  (processor s:uint32))

(define-table assembly-os #x22 ;; ii.22.3
  (os-platform-id s:uint32)
  (os-major-version s:uint32)
  (os-minor-version s:uint32))

(define-table assembly-ref #x23 ;; ii.22.5
  (major-version s:uint16)
  (minor-version s:uint16)
  (build-number s:uint16)
  (revision-number s:uint16)
  (flags assembly-flags) ;; s:uint32 ii.23.1.2
  (public-key-or-token blob-index)
  (name string-index)
  (culture string-index)
  (hash-value blob-index))

(define-table assembly-ref-processor #x24 ;; ii.22.7
  (processor s:uint32)
  (assembly-ref assembly-ref-index))

(define-table assembly-ref-os #x25 ;; ii.22.6
  (os-platform-id s:uint32)
  (os-major-version s:uint32)
  (os-minor-version s:uint32)
  (assembly-ref assembly-ref-index))

(define-table file #x26   ;; ii.22.19
  (flags file-attributes) ;; s:uint32 ii.23.1.6
  (name string-index)
  (hash-value blob-index))

(define-table exported-type #x27 ;;ii.22.14
  (flags type-attributes)
  ;; type-def-id is "index into a type-def table of another module in
  ;; this assembly", so don't think it can be expanded?
  (type-def-id s:uint32)
  (type-name string-index)
  (type-namespace string-index)
  (implementations implementation))

(define-table manifest-resource #x28
  (offset s:uint32)
  (flags manifest-resource-attributes) ;; s:uint32 ii.23.1.9
  (name string-index)
  (implementation implementation))

(define-table nested-class #x29 ;; ii.22.32
  (nested-class type-def-index)
  (enclosing-class type-def-index))

(define-table generic-param #x2a ;; ii.22.20
  (number s:uint16)
  (flags generic-param-attributes) ;; s:uint16 ii.23.1.7
  (owner type-or-method-def)
  (name string-index))

(define-table method-spec #x2b ;; ii.22.29
  (method method-def-or-ref)
  (instantiation blob-index))

(define-table generic-param-constraint #x2c ;; ii.22.21
  (owner generic-param-index)
  (constraint type-def-or-ref))

(defun name (x)
  (etypecase x
    (module (module-name x))
    (type-ref (type-ref-type-name x))
    (type-def (type-def-type-name x))
    (field (field-name x))
    (method-def (method-def-name x))
    (param (param-name x))
    (member-ref (member-ref-name x))
    (constant (name (constant-parent x)))
    (class-layout (name (class-layout-parent x)))
    (field-layout (name (field-layout-field x)))
    (module-ref (module-ref-name x))
    (impl-map (impl-map-import-name x))
    (assembly (assembly-name x))
    (assembly-ref (assembly-ref-name x))
    (custom-attribute (name (custom-attribute-type x)))
    ;; not sure exactly what these should return here
    (interface-impl (name (interface-impl-interface x)))
    (nested-class (name (nested-class-nested-class x)))
    ((eql :guid) "System.Guid")
    ((eql :void) :void)))

(defun namespace (x)
  (typecase x
    (type-def (type-def-type-namespace x))
    (type-ref (type-ref-type-namespace x))
    (exported-type (exported-type-type-namespace x))
    (t nil)))

(defun namespaced-name (x)
  (typecase x
    ;; possibly should (optionally?) intern these lists somewhere to
    ;; allow saving some space
    (type-def (list :namespace (type-def-type-namespace x)
                    :name (type-def-type-name x)))
    (type-ref (list :namespace (type-ref-type-namespace x)
                    :name (type-ref-type-name x)))
    (exported-type (list :namespace (exported-type-type-namespace x)
                         :name (exported-type-type-name x)))
    (t (name x))))

(defun namespaced-name/s (x)
  (typecase x
    ;; possibly should intern these somewhere to save some space
    (type-def (format nil "~a::~a"
                      (type-def-type-namespace x)
                      (type-def-type-name x)))
    (type-ref (format nil "~a::~a"
                      (type-ref-type-namespace x)
                      (type-ref-type-name x)))
    (exported-type (format nil "~a::~a"
                           (exported-type-type-namespace x)
                           (exported-type-type-name x)))
    (t (when x (name x)))))

(defun ns-equal (x namespace name)
  (equalp (namespaced-name x)
          (list :namespace namespace
                :name name)))


(defun parent-name (x &key namespace)
  (flet ((nname (y)
           (if namespace
               (namespaced-name y)
               (name y))))
    (typecase x
      (constant (nname (constant-parent x)))
      (custom-attribute (nname (custom-attribute-parent x)))
      (field-marshal (nname (field-marshal-parent x)))
      (decl-security (nname (decl-security-parent x)))
      (class-layout (nname (class-layout-parent x)))
      (event-map (nname (event-map-parent x)))
      (property-map (nname (property-map-parent x))))))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-table-vector (s:io-type)
    ((heap-sizes :initarg :heap-sizes :reader heap-sizes)
     (valid :initarg :valid :reader valid)
     (table-rows :initarg :table-rows :reader table-rows)))

  (defmethod s:default-value ((type io-table-vector))
    #())
  (defmethod s:lisp-type ((type io-table-vector))
    t)
  (defmethod s:octet-size ((type io-table-vector))
    '*)

  (defmethod s:write-form ((backend s:io-backend) (type io-table-vector)
                           value-variable)
    (declare (ignore type))
    `(progn
       (error "todo can't write table vector yet ~s" ,value-variable)
       ;; get rid of unused variable notes
       ,(s:write-form backend 's:uint32 123)))

  (defmethod s:read-form ((backend s:io-backend) (type io-table-vector))
    `(with-sizes (,(heap-sizes type) ,(valid type) ,(table-rows type))
       (vector
        ,@(loop for i below 64
                for table-type = (aref *tables* i)
                when table-type
                  collect `(when (logbitp ,i ,(valid type))
                             (format t "read table ~s = ~s (size ~s) @ ~x (~x) (~x)~%"
                                     ,i ',table-type
                                     (aref *table-sizes* ,i)
                                     ,(s:index-form backend)
                                     (+ *offset* ,(s:index-form backend))
                                     nil #++(- (cffi:pointer-address s::pointer)
                                               *base*))
                             (loop with l = (aref *table-sizes* ,i)
                                   with a = (make-array l :initial-element nil)
                                   for i below l
                                   do (setf (aref a i)
                                            ,(s:read-form backend table-type))
                                   finally (return a)))
                else collect nil)))))

(s:define-io-type-parser table-vector (heap-sizes valid rows)
  (make-instance 'io-table-vector
                 :heap-sizes heap-sizes
                 :valid valid :table-rows rows))

;;; structures
(s:define-io-structure stream-header
  (offset s:uint32)
  (size s:uint32)
  (name pad-string))

(defmethod s::extra-bindings ((name (eql 'header)))
  `((string-cache (make-hash-table))
    (guid-cache (make-hash-table))
    (blob-cache (make-hash-table))))

(s:define-io-structure ~stream
  (reserved s:uint32) ;; 0
  (major s:uint8)     ;; 2
  (minor s:uint8)     ;; 0
  (heap-sizes (s::flags s:uint8
                  (1 :string)
                (2 :guid)
                (4 :blob)
                ;;?
                (8 :us)))
  (res2 s:uint8) ;; 1
  (valid s:uint64)
  (sorted s:uint64)
  (rows (vector s:uint32 (logcount (s:slot valid))))
  (tables (table-vector (s:slot heap-sizes) (s:slot valid) (s:slot rows))))

(s:define-io-structure header
  "BSJB"                                ;#x424a5342
  (major s:uint16)                      ;; 1
  (minor s:uint16)                      ;; 1
  (reserved s:uint32)                   ;; 0
  (version-length s:uint32)
  (version (string (s:slot version-length)))
  (flags s:uint16) ;; 0
  (stream-count s:uint16)
  (streams (vector stream-header (s:slot stream-count)) :bind *streams*)
  (~ ~stream :offset (stream-header-offset
                      (find "#~" (s:slot streams)
                            :key 'stream-header-name
                            :test 'string=)))
  (string-heap (vector s:uint8 (stream-header-size
                                (find "#Strings" (s:slot streams)
                                      :key 'stream-header-name
                                      :test 'string=)))
               :offset (stream-header-offset
                        (find "#Strings" (s:slot streams)
                              :key 'stream-header-name
                              :test 'string=)))
  (guid-heap (vector s:uint8 (stream-header-size
                              (find "#GUID" (s:slot streams)
                                    :key 'stream-header-name
                                    :test 'string=)))
             :offset (stream-header-offset
                      (find "#GUID" (s:slot streams)
                            :key 'stream-header-name
                            :test 'string=)))
  (us-heap (vector s:uint8 (stream-header-size
                            (find "#US" (s:slot streams)
                                  :key 'stream-header-name
                                  :test 'string=)))
           :offset (stream-header-offset
                    (find "#US" (s:slot streams)
                          :key 'stream-header-name
                          :test 'string=)))
  (blob-heap (vector s:uint8 (stream-header-size
                              (find "#Blob" (s:slot streams)
                                    :key 'stream-header-name
                                    :test 'string=)))
             :offset (stream-header-offset
                      (find "#Blob" (s:slot streams)
                            :key 'stream-header-name
                            :test 'string=))))


(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass blob-packed-int (s:numeric-type)
    ((signed-p :initarg :signed-p :initform T :accessor signed-p)))
  (defmethod s:default-value ((type blob-packed-int))
    0)
  (defmethod s:initargs append ((type blob-packed-int))
    (list :signed-p (signed-p type)))

  (defmethod s:lisp-type ((type blob-packed-int))
    `(or null
         (,(if (signed-p type) 'signed-byte 'unsigned-byte) 29)))

  (defmethod s:read-form ((backend s:io-backend) (type blob-packed-int))
    (flet ((signed (w)
             (when (signed-p type)
               `(setf l
                      (if (logbitp 0 l)
                          (dpb (ldb (byte ,w 1) l) (byte ,w 0) -1)
                          (ldb (byte ,w 1) l))))))
      `(let* ((s ,(s:read-form backend 's:uint8)))
         (case (ldb (byte 3 5) s)
           ;; top bit 0x, use low 7 bits
           ((#b000 #b001 #b010 #b011)
            (let ((l (ldb (byte 7 0) s)))
              ,(signed 6)
              l))
           ;; top bits 10, use low 6 bits and next byte
           ((#b100 #b101)
            (let ((l (+ (ash (ldb (byte 6 0) s) 8)
                        ,(s:read-form backend 's:uint8))))
              ,(signed 13)
              l))
           ;; top bits 110, use low 5 bits and next 3 bytes
           ((#b110)
            (let ((l (+ (ash (ldb (byte 5 0) s) 24)
                        (ash ,(s:read-form backend 's:uint8) 16)
                        (ash ,(s:read-form backend 's:uint8) 8)
                        ,(s:read-form backend 's:uint8))))
              ,(signed 28)
              l))
           ;; all bits set = "null string" marker, else error
           (#b111
            (if (= s #xff)
                nil
                (error "unrecognized packed integer ~8,'0b?" s)))))))

  (defmethod s:write-form ((backend s:io-backend) (type blob-packed-int) v)
    (flet ((signed (w)
             (if (signed-p type)
                 `(logior (ash (ldb (byte ,w 0) ,v) 1)
                          (ldb (byte 1 ,w) ,v))
                 v)))
      `(cond
         ((eql ,v nil)
          ,(s:write-form backend 's:uint8 #xff))
         (t
          (cond
            ((<= #.(- (expt 2 6)) ,v #.(1- (expt 2 6)))
             ,(s:write-form backend 's:uint8 (signed 6)))
            (t
             (error "todo: write packed ints ~s" ,v))))))))

(s:define-io-type-parser pint ()
  (make-instance 'blob-packed-int :octet-size '* :signed-p t :order :packed))
(s:define-io-type-parser puint ()
  (make-instance 'blob-packed-int :octet-size '* :signed-p nil :order :packed))


(s:define-io-structure packed-uint-test
  (s puint))
;; todo: test uint

(s:define-io-structure packed-int-test
  (s pint))

#++
(let ((tests '((3 (#x06))
               (-3 (#x7b))
               (64 (#x80 #x80))
               (-64 (#x01))
               (8192 (#xc0 #x00 #x40 #x00))
               (-8192 (#x80 #x01))
               (268435455 (#xdf #xff #xff #xfe))
               (-268435456 (#xc0 #x00 #x00 #x01))
               (nil (#xff)))))
  (loop for (x b) in tests
        do (assert (eql x
                        (packed-int-test-s
                         (read-packed-int-test (apply 'octet-vector b)))))))

(enum native-type s:uint8
  (#x02 :boolean)
  (#x03 :i1)
  (#x04 :u1)
  (#x05 :i2)
  (#x06 :u2)
  (#x07 :i4)
  (#x08 :u4)
  (#x09 :i8)
  (#x0a :u8)
  (#x0b :r4)
  (#x0c :r8)
  (#x14 :lpstr)
  (#x15 :lpwstr)
  (#x1f :int)
  (#x20 :uint)
  (#x26 :func)
  (#x2a :array))

(flags signature-flags s:uint8
  ((ldb (byte 5 0)) :conv ;; supposedly 4 bits, but also includes #x10?
   (#x0 :default)
   (#x1 :c)
   (#x2 :stdcall)
   (#x3 :thiscall)
   (#x4 :fastcall)
   (#x5 :vararg)
   (#x6 :field)
   (#x7 :local)
   (#x8 :property)
   (#xa :prolog)
   ;; this might actually be a separate flag that is only usable with
   ;; :default, but spec describes it as "default | vararg | generic",
   ;; so including it in the "4"-bit calling convention
   (#x10 :generic)) ;; has generic parameters
  (#x20 :has-this)
  (#x40 :explicit-this))

;; vector of loaded tables used to expand refs while parsing blobs
(defvar *current-tables* nil)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass type-def-or-ref-or-spec-encoded (blob-packed-int)
    ()
    (:default-initargs :signed-p nil :octet-size '*))

  (defmethod s:read-form :around (backend (type type-def-or-ref-or-spec-encoded))
    `(let* ((enc ,(call-next-method))
            (table (ldb (byte 2 0) enc))
            (table-id (ecase table (0 'type-def) (1 'type-ref) (2 'type-spec)))
            (row (ldb (byte 24 2) enc)))
       (declare (optimize (speed 0) safety debug
                          (sb-c::insert-array-bounds-checks 1)))
       #++(format t "tdorose ~s=~s,~s enc=~32,'0,',4b~%"
                  table table-id row enc)
       (when *current-tables*
         (unless (array-in-bounds-p
                  (aref *current-tables* (gethash table-id *table-index*))
                  (1- row))
           (break "tdorose table ~s = ~s row ~s (enc #x~x)~% table = ~s"
                  table-id (gethash 'type-def *table-index*) row enc
                  (aref *current-tables* (gethash table-id *table-index*)))))
       (if *current-tables*
           (aref (aref *current-tables* (gethash table-id *table-index*))
                 (1- row))
           (make-instance 'table-ref :table table-id :index row))))

  (defmethod s:lisp-type ((c type-def-or-ref-or-spec-encoded))
    t))

(s:define-io-type-parser type-def-or-ref-or-spec-encoded ()
  (make-instance 'type-def-or-ref-or-spec-encoded))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defclass io-element-sequence (s:io-type)
    ;; todo: add restrictions on sequence or grammar? for now just
    ;; allowing whatever is there and terminating on specific types
    ())

  (defmethod s:initargs append ((s io-element-sequence))
    nil)

  (defmethod s:default-value ((type io-element-sequence))
    ())

  (defmethod s:lisp-type ((type io-element-sequence))
    'list)

  (defmethod s:octet-size ((type io-element-sequence))
    '*)

  (defmethod s:read-form ((backend s:io-backend) (type io-element-sequence))
    `(let ((d 0))
       (labels
           ((element ()
              (when (> (incf d) 10)
                (break "looped?"))
              (loop
                with done = nil
                for tag = ,(s:read-form backend 'element-type)
                for d = 0
                append (labels ((end ()
                                  (setf done t)
                                  `(:type ,tag))
                                (tdorose (&key end)
                                  (when end (setf done t))
                                  (list tag ,(s:read-form backend
                                                          'type-def-or-ref-or-spec-encoded)))
                                (array-shape ()
                                  (let* ((rank ,(s:read-form backend 'puint))
                                         (sizes ,(s:read-form backend 'puint))
                                         (size
                                           (loop repeat sizes
                                                 collect ,(s:read-form backend 'puint)))
                                         (num-lo-bounds ,(s:read-form backend 'puint))
                                         (lo-bound
                                           (loop repeat num-lo-bounds
                                                 collect ,(s:read-form backend 'puint))))
                                    (list :Rank rank :sizes size :low lo-bound)))
                                (array ()
                                  (setf done t)
                                  ;; not sure how complex the type here can be,
                                  ;; hopefully reading another element-sequence
                                  ;; works? (should be just a single type, but
                                  ;; could be arbitrary complex... arrays of
                                  ;; arrays of pointers to classes or whatever?)
                                  (let ((type (element))
                                        (shape (array-shape)))
                                    `(:array ,type ,@shape)))
                                (err ()
                                  (error "got unexpected element type ~s?" tag))
                                (todo ()
                                  (break "element type ~s not implemented yet" tag)))
                         (ecase tag
                           (:END (end))
                           (:VOID (end))
                           (:BOOLEAN (end))
                           (:CHAR (end))
                           (:I1 (end))
                           (:U1 (end))
                           (:I2 (end))
                           (:U2 (end))
                           (:I4 (end))
                           (:U4 (end))
                           (:I8 (end))
                           (:U8 (end))
                           (:R4 (end))
                           (:R8 (end))
                           (:STRING (end))
                           (:PTR '(:ptr t))       ;; Followed by type
                           (:BY-REF '(:by-ref t)) ;; Followed by type
                           (:VALUE-TYPE (tdorose :end t)) ;; Followed by TypeDef or TypeRef token
                           (:CLASS (tdorose :end t)) ;; Followed by TypeDef or TypeRef token
                           (:VAR (todo)) ;; Generic parameter in a generic type definition, represented as number (compressed unsigned integer)
                           (:ARRAY (array)) ;; type rank boundsCount bound1 … loCount lo1 …
                           (:GENERIC-INST (todo)) ;; Generic type instantiation. Followed by type type-arg-count type-1 ... type-n
                           (:TYPED-BY-REF (end))
                           (:I (end)) ;;System.IntPtr
                           (:U (end)) ;; System.UIntPtr
                           (:FNPTR (todo)) ;; Followed by full method signature
                           (:OBJECT (end)) ;; System.Object
                           (:SZARRAY (todo)) ;; Single-dim array with 0 lower bound
                           (:MVAR (todo)) ;; Generic parameter in a generic method definition, represented as number (compressed unsigned integer)
                           (:CMOD-REQD (tdorose)) ;; Required modifier : followed by a TypeDef or TypeRef token
                           (:CMOD-OPT (tdorose)) ;; Optional modifier : followed by a TypeDef or TypeRef token
                           (:INTERNAL (todo)) ;; Implemented within the CLI
                           (:MODIFIER (todo)) ;; Or’d with following element types

                           ;; would be nicer to split vararg marker into a
                           ;; separate item, but it is optional and we get a
                           ;; count that doesn't include it when it is there so
                           ;; just adding to next argument for now, and can
                           ;; split later if needed
                           (:SENTINEL '(:vararg-start t)) ;; Sentinel for vararg method signature
                           (:PINNED `(,tag t)) ;; Denotes a local variable that points at a pinned object
                           (:system.type (todo)) ;; Indicates an argument of type System.Type.
                           (:custom/boxed-object (todo)) ;; Used in custom attributes to specify a boxed object (§II.23.3).
                           (:reserved (err))             ;;Reserved
                           (:custom/field (todo)) ;; Used in custom attributes to indicate a FIELD (§II.22.10, II.23.3).
                           (:custom/property (todo)) ;; Used in custom attributes to indicate a PROPERTY (§II.22.10, II.23.3).
                           (:custom/enum (todo)))) ;; Used in custom attributes to specify an enum (§II.23.3)
                until done)))
         (element))))

  (defmethod s:write-form ((backend s:io-backend) (type io-element-sequence) w)
    `(loop for i in ,w
           do (etypecase i
                (keyword
                 ,(s:write-form backend 'element-type 'i))
                (t
                 (error "todo: write complex element-types"))))))

(s:define-io-type-parser element-sequence ()
  (make-instance 'io-element-sequence))

;; vararg sentinel = #x41
(s:define-io-structure blob-signature
  (flags signature-flags)
  (gen-param-count (typecase (s:slot flags-conv)
                     ((eql :generic) puint)
                     (t nil)))
  (param-count (typecase (s:slot flags-conv)
                 ((eql :field) 1)
                 (t puint)))
  (return-type (typecase (s:slot flags-conv)
                 ;; function types have return values :field and :local,
                 ;; don't
                 ((not (member :field :local :prolog))
                  #++(member :default :c :stdcall :thiscall
                             :fastcall :vararg :generic :property)
                  element-sequence)
                 (t nil)))
  (param (vector element-sequence (s:slot param-count))))


(s:define-io-structure blob-field
  (flags signature-flags) ;; #x06 = field
  (field  element-sequence))

(s:define-io-structure blob-property-type
  (flags signature-flags) ;; :conv = :property
  (param-count puint)
  (return-type element-sequence)
  (param (vector element-sequence (s:slot param-count))))

(defmethod update-table-ref (x header row field)
  x)

(defvar *foo* nil)
(defvar *attributes* (make-hash-table :test 'equal))

;; used by AttributeUsageAttributes custom attribute
(s::define-io-flags attribute-targets s:uint32 ;; is this right size?
  (1 :assembly)
  (2 :module)
  (4 :class)
  (8 :struct)
  (16 :enum)
  (32 :constructor)
  (64 :method)
  (128 :property)
  (256 :field)
  (512 :event)
  (1024 :interface)
  (2048 :parameter)
  (4096 :delegate)
  (8192 :return-value)
  (16384 :generic-parameter)
  (32767 :all))

;; used by SupportedArchitectureAttribute
(s::define-io-flags architecture s:uint32 ;; is this right size?
  (1 :x86)
  (2 :x64)
  (4 :arm64)
  (7 :all))

(defmethod update-table-ref ((x heap-ref) header row field)
  (let ((index (index x)))
    (ecase (heap x)
      (:string
       (let* ((heap (header-string-heap header))
              (e (position 0 heap :start index)))
         (assert e)
         (babel:octets-to-string heap :start index :end e :encoding :utf-8)))
      (:guid
       (let ((heap (header-guid-heap header))
             (offset (* 16 (1- index))))
         (subseq heap offset (+ offset 16))))
      (:blob
       (let* ((heap (header-blob-heap header))
              (offset index)
              (end (length heap)))
         (macrolet ((use (n &body body)
                      `(prog2 (assert (<= (+ offset ,n) end))
                           (progn ,@body)
                         (incf offset ,n))))
           (labels ((u8 ()
                      (use 1 (aref heap offset)))
                    (s8 ()
                      (use 1 (let ((u (aref heap offset)))
                               (if (logbitp 7 u)
                                   (dpb u (byte 8 0) -1)
                                   u))))
                    (u16 ()
                      (use 2 (nibbles:ub16ref/le heap offset)))
                    (s16 ()
                      (use 2 (nibbles:sb16ref/le heap offset)))
                    (u32 ()
                      (use 4 (nibbles:ub32ref/le heap offset)))
                    (s32 ()
                      (use 4 (nibbles:sb32ref/le heap offset)))
                    (u64 ()
                      (use 8 (nibbles:ub64ref/le heap offset)))
                    (s64 ()
                      (use 8 (nibbles:ub64ref/le heap offset)))
                    (f32 ()
                      (use 4 (nibbles:ieee-single-ref/le heap offset)))
                    (f64 ()
                      (use 8 (nibbles:ieee-double-ref/le heap offset)))
                    (et ()
                      (ecase (u8)
                        (#x01 :VOID)
                        (#x02 :BOOLEAN)
                        (#x03 :CHAR)
                        (#x04 :I1)
                        (#x05 :U1)
                        (#x06 :I2)
                        (#x07 :U2)
                        (#x08 :I4)
                        (#x09 :U4)
                        (#x0a :I8)
                        (#x0b :U8)
                        (#x0c :R4)
                        (#x0d :R8)
                        (#x0e :STRING)
                        (#x53 :field)
                        (#x54 :property)
                        (#x55 :enum)))
                    (upack ()
                      (let ((s (u8)))
                        (case (ldb (byte 3 5) s)
                          ((#b000 #b001 #b010 #b011)
                           (ldb (byte 7 0) s))
                          ((#b100 #b101)
                           (+ (ash (ldb (byte 6 0) s) 8)
                              (u8)))
                          ;; top bits 110, use low 5 bits and next 3 bytes
                          ((#b110)
                           (+ (ash (ldb (byte 5 0) s) 24)
                              (ash (u8) 16)
                              (ash (u8) 8)
                              (u8)))
                          ;; all bits set = "null string" marker, else error
                          (#b111
                           (if (= s #xff)
                               nil
                               (error "unrecognized packed integer ~8,'0b?" s))))))
                    (u8string ()
                      (let ((l (upack)))
                        (if l
                            (prog1
                                (babel:octets-to-string heap
                                                        :start offset
                                                        :end (+ offset l)
                                                        :encoding :utf-8)
                              (incf offset l))
                            ""))))
             (let ((length (upack)))
               (assert (<= (+ offset length) end))
               (setf end (+ offset length))
               (when (> length (- (length heap) offset))
                 (break "out of range ~s?~% ~8,'0b ~8,'0b ~8,'0b ~8,'0b~%~x~%~x"
                        length
                        (aref heap (+ index -1))
                        (aref heap (+ index 0))
                        (aref heap (+ index 1))
                        (aref heap (+ index 2))
                        (subseq heap (max 0 (- index 32)) index)
                        (subseq heap index (+ index 255))))
               (prog1
                   (if (not length)
                       nil
                       (ecase field
                         (constant-value
                          (case (constant-type row)
                            (:u1 (u8))
                            (:i1 (s8))
                            (:u2 (u16))
                            (:i2 (s16))
                            (:u4 (u32))
                            (:i4 (s32))
                            (:u8 (u64))
                            (:i8 (s64))
                            (:r4 (f32))
                            (:r8 (f64))
                            (:string ;; utf16?
                             (babel:octets-to-string heap
                                                     :start offset :end end
                                                     :encoding :utf-16/le))
                            (t (error "todo: constant type ~s~%" (constant-type row)))))
                         ((method-def-signature ;; ii.23.2.1
                           member-ref-signature ;; ii.23.2.2, ii.23.2.4
                           stand-alone-sig-signature ;; ii.23.2.3, ii.23.2.6
                           field-signature           ;; ii.23.2.4
                           property-type)            ;; ii.23.2.5
                          (let ((b (read-blob-signature heap
                                                        :start offset :end end)))
                            (ecase field
                              (field-signature
                               (assert (eql (blob-signature-flags-conv b)
                                            :field)))
                              (member-ref-signature
                               (assert (member (blob-signature-flags-conv b)
                                               '(:default :vararg :field :generic))))
                              (method-def-signature
                               (assert (member (blob-signature-flags-conv b)
                                               '(:default :vararg :generic
                                                 ;; spec doesn't include
                                                 ;; thiscall, but file
                                                 ;; does
                                                 :thiscall))))
                              (property-type
                               (assert (eql (blob-signature-flags-conv b)
                                            :property)))
                              (stand-alone-sig-signature
                               (assert (member (blob-signature-flags-conv b)
                                               '(:method :locals)))))
                            b))
                         ;; this has a special parser, see ii.23.3 and see
                         ;; restrictions in ii.22.10
                         (custom-attribute-value
                          ;; version info is stored in custom-attribute with
                          ;; row.type.class.type-name =
                          ;; "SupportedOSPlatformAttribute" need to parse
                          ;; row.type.signature to parse this though, so
                          ;; might need to be second pass depending on if
                          ;; those tables have already been updated yet or
                          ;; not?

                          ;; also stores documentation links, const flags,
                          ;; char width flag (ansi/unicode=wide), etc

                          ;; AgileAttribute, AlsoUsableForAttribute,
                          ;; AnsiAttribute, AssociatedConstantAttribute,
                          ;; AssociatedEnumAttribute,
                          ;; AttributeUsageAttribute,
                          ;; CanReturnErrorsAsSuccessAttribute,
                          ;; CanReturnMultipleSuccessValuesAttribute,
                          ;; ComOutPtrAttribute, ComVisibleAttribute,
                          ;; ConstAttribute, ConstantAttribute,
                          ;; DoNotReleaseAttribute, DocumentationAttribute,
                          ;; DoesNotReturnAttribute, FlagsAttribute,
                          ;; FlexibleArrayAttribute, FreeWithAttribute,
                          ;; GuidAttribute, IgnoreIfReturnAttribute,
                          ;; InvalidHandleValueAttribute,
                          ;; MemorySizeAttribute, MetadataTypedefAttribute,
                          ;; NativeArrayInfoAttribute,
                          ;; NativeBitfieldAttribute,
                          ;; NativeEncodingAttribute,
                          ;; NativeTypedefAttribute,
                          ;; NotNullTerminatedAttribute,
                          ;; NullNullTerminatedAttribute, ObsoleteAttribute,
                          ;; RAIIFreeAttribute, ReservedAttribute,
                          ;; RetValAttribute, ScopedEnumAttribute,
                          ;; StructSizeFieldAttribute,
                          ;; SupportedArchitectureAttribute,
                          ;; SupportedOSPlatformAttribute, UnicodeAttribute,
                          ;; UnmanagedFunctionPointerAttribute

                          ;; "named args" part (starting with NumNamed) is
                          ;; shared with decl-security-permission-set, so
                          ;; factor that out if possible
                          (let* ((ctor (custom-attribute-type row))
                                 (sig (member-ref-signature ctor))
                                 (blob (subseq heap offset end)))
                            (assert (typep ctor 'member-ref))
                            (assert (equalp (member-ref-name ctor) ".ctor"))
                            (assert (= 1 (u16)))
                            (labels ((elem (p type)
                                       (case type
                                         (:string
                                          (u8string))
                                         (:boolean
                                          (not (zerop (u8))))
                                         (:char
                                          (code-char (u16)))
                                         (:u1 (u8))
                                         (:i1 (s8))
                                         (:u2 (u16))
                                         (:i2 (s16))
                                         (:u4 (u32))
                                         (:i4 (s32))
                                         (:u8 (u64))
                                         (:i8 (s64))
                                         (:r4 (f32))
                                         (:r8 (f64))
                                         (:custom/boxed-object
                                          (let ((et (et)))
                                            (elem p et)))
                                         ((nil)
                                          (let* ((vt (getf p :value-type)))
                                            (assert vt)
                                            (cond
                                              ;; todo: factor this out
                                              ;; and add keywords for
                                              ;; the enums
                                              ((and (typep vt 'type-ref)
                                                    (position
                                                     (type-ref-type-name vt)
                                                     '("CallingConvention"
                                                       "AttributeTargets"
                                                       "Architecture")
                                                     :test 'string=))
                                               ;; enum
                                               (u32))
                                              (t
                                               (break "vt ~s ~s~% ~s ~s~%~s"
                                                      (etypecase vt
                                                        (type-def
                                                         (type-def-type-name vt))
                                                        (type-ref
                                                         (type-ref-type-name vt)))
                                                      blob (u8) nil ;(elem p et)
                                                      (subseq heap offset end))))))
                                         (t (break "unexpected enum ~s?"
                                                   type)
                                          :???))))
                              (append
                               (loop for p across (blob-signature-param sig)
                                     for type = (getf p :type)
                                     collect (elem p type))
                               (let ((nnamed (u16)))
                                 (unless (zerop nnamed)
                                   (let ((s (- offset index))
                                         (r (loop for i below nnamed
                                                  for fp = (et)
                                                  for et = (et)
                                                  collect (list fp
                                                                et
                                                                (u8string)
                                                                (elem nil et)))))
                                     (unless (= offset end)
                                       (break "todo named args ~s~%~s ~s~%~s" nnamed
                                              s blob
                                              r))
                                     r)))))))
                         ;; probably can just return the blob (and/or
                         ;; ignore it?)
                         ((assembly-public-key
                           assembly-ref-hash-value
                           assembly-ref-public-key-or-token
                           file-hash-value)
                          (list field (unless (zerop length)
                                        (subseq heap offset end))))
                         ;; probably should be parsed, but don't have
                         ;; any currently
                         ((field-marshal-native-type ;; ii.23.4 ?
                           type-spec-signature
                           method-spec-instantiation
                           decl-security-permission-set)
                          (break "todo ~s" field)
                          (list :blob field
                                (unless (zerop length)
                                  (subseq heap offset end))))
                         (t
                          (break "field ~s" field)
                          (list :blob index offset length
                                (unless (zerop length)
                                  (subseq heap offset end)
                                  #++
                                  (read-blob heap :start offset :end end))))))))))))
      (:us
       (break "us ~a "(list :todo :us index))))))

(defmethod update-table-ref ((x table-ref) header row field)
  (unless (zerop (index x))
    (let* ((index (index x))
           (table-index (table x))
           (table (aref (~stream-tables (header-~ header)) table-index)))
      (unless table
        (break "missing table ~s in ~s?~% index ~s" table-index x index))
      (if (= (1- index) (length table))
          ;; not sure if there is a difference between 0 and
          ;; end-of-table markers for null?
          (list :null (aref *tables* table-index))
          (aref table (1- index))))))

(defun update-table-refs (header)
  (let ((*current-tables* (~stream-tables (header-~ header))))
    (loop for table across (~stream-tables (header-~ header))
          when table
            do (loop for i below (length table)
                     for row = (aref table i)
                     for next = (when (< (1+ i) (length table))
                                  (aref table (1+ i)))
                     do (update-refs row header next)))))

;;; todo: merge all these into a class or something
(defvar *file* nil)
(defun get-table (header field)
  (aref (~stream-tables (header-~ header))
        (gethash field *table-index* field)))
;; various tables for looking up inverse links
(defvar *layout-index* (make-hash-table)) ;; by parent or field
(defvar *constant-index* (make-hash-table)) ;; by parent
(defvar *attribute-index* (make-hash-table)) ;; by parent
;; probably more useful to just convert attributes to a plist
(defvar *attribute-plist* (make-hash-table)) ;; by parent
(defvar *impl-map-index* (make-hash-table)) ;; by member-forwarded
(defvar *interface-impl-index* (make-hash-table)) ;; by class
(defvar *nested-class-index* (make-hash-table)) ;; nested-class by nested-class
(defvar *enclosing-class-index* (make-hash-table)) ;; nested-class by enclosing-class
(defvar *extends-index* (make-hash-table)) ;; type-def by extends?
(defvar *type-def-by-name* (make-hash-table :test 'equal)) ;; type-def by ("namespace" "name")
;;; calculated size/alignment for types
;; type-def instance -> (octet-size alignment next-type)
;;; (next-type is either type-def, type-ref, or one of the base types
;;;  :u1,s2,r4,etc. Might be same object as key for struct/union types
;;;  or another type for typedefs, no attempt is made to collapse
;;;  chains of typedefs.)

(defvar *type-def-info* (make-hash-table))
(defvar *base-types* (a:alist-hash-table
                      ;; todo: make this configurable so we can
                      ;; generate x86 from x64?
                      (let ((ps (cffi:foreign-type-size :pointer)))
                        ;; name size alignment ffi name
                        `((:u1 1 1 :uint8)
                          (:i1 1 1 :int8)
                          (:u2 2 2 :uint16)
                          (:i2 2 2 :int16)
                          (:u4 4 4 :uint32)
                          (:i4 4 4 :int32)
                          (:u8 8 8 :uint64)
                          (:i8 8 8 :int64)
                          (:u ,ps ,ps :uintptr)
                          (:i ,ps ,ps :intptr)
                          (:r4 4 4 :float)
                          (:r8 8 8 :double)
                          (:ptr ,ps ,ps :pointer)
                          ;; pointer to System.String, not char*
                          (:string ,ps ,ps :pointer)
                          ;; pointer to (subclass of) System.Object?
                          (:class ,ps ,ps :pointer)
                          ;; wchar
                          (:char 2 2 :uint16)
                          ;; todo: verify size of this particular bool
                          ;; might be 1,1,(:boolean :uint8) and
                          ;; "Windows.Win32.Foundation::BOOL" is the
                          ;; 4,4,uint one?
                          (:boolean 4 4 (:boolean :uint))
                          (:guid 4 16 :guid)
                          (:void 0 0 :void)))))

(defun reset-type-def-info (h)
  (clrhash *type-def-info*)
  (loop with ps = (cffi:foreign-type-size :pointer)
        for tt in (a:hash-table-keys *base-types*)
        for (ts ta) = (gethash tt *base-types*)
        do (setf (gethash tt *type-def-info*) (list ts ta tt)))
  (let ((guid (find "Guid" (get-table h 'type-ref)
                    :key 'type-ref-type-name
                    :test 'string-equal)))
    ;; https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid defines it as a struct with a long, so align 4?
    (setf (gethash guid *type-def-info*) (list 16 4 :guid)))
  *type-def-info*)

(defun custom-attribute-plist (x)
  (let ((class (etypecase (custom-attribute-type x)
                 (member-ref
                  (member-ref-class (custom-attribute-type x)))))
        (value (custom-attribute-value x)))
    (macrolet ((att-switch (&body clauses)
                 `(cond
                    ,@(loop for (name . body) in clauses
                            if (eql name t)
                              collect `(t ,@body)
                            else collect `((ns-equal class ,@name)
                                           ,@body)))))
      (att-switch
       (("Windows.Win32.Foundation.Metadata" "AgileAttribute")
        (assert (eql value nil))
        `(:agile-p t))
       (("Windows.Win32.Foundation.Metadata" "AnsiAttribute")
        (assert (eql value nil))
        `(:string-type :ansi))
       (("Windows.Win32.Foundation.Metadata" "UnicodeAttribute")
        (assert (eql value nil))
        `(:string-type :unicode))
       (("Windows.Win32.Foundation.Metadata" "DocumentationAttribute")
        (assert (stringp (car value)))
        (assert (= 1 (length value)))
        `(:documentation ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "AssociatedConstantAttribute")
        (assert (= 1 (length value)))
        `(:associated-constant ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "SupportedOSPlatformAttribute")
        (assert (= 1 (length value)))
        (assert (stringp (car value)))
        `(:supported-os ,(intern (string-upcase (car value)) :keyword)))
       (("Windows.Win32.Foundation.Metadata" "GuidAttribute")
        `(:guid ,value))
       (("Windows.Win32.Foundation.Metadata" "SupportedArchitectureAttribute")
        (assert (= 1 (length value)))
        `(:supported-architecture ,(architecture-as-keys (car value))))
       (("Windows.Win32.Foundation.Metadata" "StructSizeFieldAttribute")
        (assert (= 1 (length value)))
        `(:structure-size-field ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "NativeTypedefAttribute")
        (assert (eql value nil))
        `(:native-typedef t))
       (("Windows.Win32.Foundation.Metadata" "RAIIFreeAttribute")
        (assert (= 1 (length value)))
        `(:raii-free ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "InvalidHandleValueAttribute")
        (assert (= 1 (length value)))
        `(:invalid-handle-value ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "AlsoUsableForAttribute")
        (assert (= 1 (length value)))
        `(:also-usable-for ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "MetadataTypedefAttribute")
        (assert (eql value nil))
        '(:metadata-typedef t))
       (("Windows.Win32.Foundation.Metadata" "ScopedEnumAttribute")
        (assert (eql value nil))
        '(:scoped-enum t))
       (("Windows.Win32.Foundation.Metadata" "AssociatedEnumAttribute")
        (assert (= 1 (length value)))
        `(:associated-enum ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "ConstAttribute")
        (assert (eql value nil))
        '(:const t))
       (("Windows.Win32.Foundation.Metadata" "NativeArrayInfoAttribute")
        (loop for (field type name avalue) in value
              do (assert (eql field :field))
                 (assert (member type '(:i2 :i4 :string)))
              append (a:eswitch (name :test string=)
                       ("CountConst"
                        (list :count-const avalue))
                       ("CountParamIndex"
                        (list :count-param-index avalue))
                       ("CountFieldName"
                        (list :count-field-name avalue)))))
       (("Windows.Win32.Foundation.Metadata" "ReservedAttribute")
        (assert (eql value nil))
        '(:reserved t))
       (("Windows.Win32.Foundation.Metadata" "MemorySizeAttribute")
        (loop for (field type name avalue) in value
              do (assert (eql field :field))
                 (assert (eql type :i2))
              append (a:eswitch (name :test string=)
                       ("BytesParamIndex"
                        (list :bytes-param-index avalue)))))
       (("Windows.Win32.Foundation.Metadata" "ComOutPtrAttribute")
        (assert (eql value nil))
        '(:com-out-ptr t))
       (("Windows.Win32.Foundation.Metadata" "NotNullTerminatedAttribute")
        (assert (eql value nil))
        '(:not-null-terminated t))
       (("Windows.Win32.Foundation.Metadata" "NullNullTerminatedAttribute")
        (assert (eql value nil))
        '(:null-null-terminated t))
       (("Windows.Win32.Foundation.Metadata" "CanReturnErrorsAsSuccessAttribute")
        (assert (eql value nil))
        '(:can-return-errors-as-success t))
       (("Windows.Win32.Foundation.Metadata" "CanReturnMultipleSuccessValuesAttribute")
        (assert (eql value nil))
        '(:can-return-multiple-success-values t))
       (("Windows.Win32.Foundation.Metadata" "FreeWithAttribute")
        (assert (= 1 (length value)))
        `(:free-with ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "ConstantAttribute")
        (assert (= 1 (length value)))
        `(:constant ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "DoNotReleaseAttribute")
        (assert (eql value nil))
        '(:do-not-release t))
       (("Windows.Win32.Foundation.Metadata" "IgnoreIfReturnAttribute")
        (assert (= 1 (length value)))
        `(:ignore-if-return-is ,(car value)))
       (("Windows.Win32.Foundation.Metadata" "RetValAttribute")
        (assert (eql value nil))
        '(:ret-value t))
       (("Windows.Win32.Foundation.Metadata" "NativeEncodingAttribute")
        (assert (= 1 (length value)))
        `(:native-encoding ,(intern (string-upcase (car value)) :keyword)))
       (("Windows.Win32.Foundation.Metadata" "NativeBitfieldAttribute")
        ;; probably want to combine these on parent?
        (destructuring-bind (name start size) value
          `(:bit-field (,name (byte ,start ,(+ start size))))))
       (("Windows.Win32.Foundation.Metadata" "FlexibleArrayAttribute")
        (assert (eql value nil))
        '(:flexible-array t))


       (("System" "ObsoleteAttribute")
        (assert (< (length value) 2))
        `(:obsolete ,(or (car value) t)))
       (("System" "AttributeUsageAttribute")
        (list :attribute-usage
              (list* :valid-on (attribute-targets-as-keys (car value))
                     (loop for (field type name avalue) in (cdr value)
                           do (assert (eql field :field))
                              (assert (eql type :boolean))
                           append (a:eswitch (name :test string=)
                                    ("AllowMultiple"
                                     (list :allow-multiple avalue))
                                    ("Inherited"
                                     (list :inherited avalue)))))))
       (("System" "FlagsAttribute")
        (assert (eql value nil))
        `(:flag-p t))
       (("System.Diagnostics.CodeAnalysis" "DoesNotReturnAttribute")
        (assert (eql value nil))
        '(:does-not-return t))
       (("System.Runtime.InteropServices" "ComVisibleAttribute")
        `(:com-visible ,value))
       (("System.Runtime.InteropServices" "UnmanagedFunctionPointerAttribute")
        (assert (= 1 (length value)))
        ;; no idea what these mean
        `(:unmanaged-function-pointer ,(car value)))

       (t
        (let ((n (namespaced-name class)))
          (break "todo: custom attribute~%(~s ~s)~%~s"
                 (getf n :namespace) (getf n :name)
                 x)))))))

(defvar *list-attributes*
  ;; custom attributes which are allowed to appear multiple times
  '(:associated-constant :Associated-enum :ignore-if-return-is
    :bit-field :invalid-handle-value))

;; we need to filter indices by architecture to make sure we find the
;; right thing when searching by name
(defvar *architecture* :x64) ;; :x86, :x64, or :arm64

(defun update-indices (header)
  (map nil 'clrhash (list *layout-index* *constant-index* *attribute-index*
                          *impl-map-index* *interface-impl-index*
                          *nested-class-index* *enclosing-class-index*
                          *extends-index* *type-def-by-name*))
  ;; class and field layouts in same table since it is obvious which
  ;; is which from key
  (loop for i across (get-table header 'class-layout)
        ;; 1 layout per class
        do (assert (not (gethash (class-layout-parent i) *layout-index*)))
           (setf (gethash (class-layout-parent i) *layout-index*) i))
  (loop for i across (get-table header 'field-layout)
        do (assert (not (gethash (field-layout-field i) *layout-index*)))
           (setf (gethash (field-layout-field i) *layout-index*) i))
  (loop for i across (get-table header 'custom-attribute)
        for parent = (custom-attribute-parent i)
        for pl = (custom-attribute-plist i)
        do (push i (gethash parent *attribute-index*))
           (loop for (k v) on pl by #'cddr
                 do (cond
                      ((member k *list-attributes*)
                       (push v (getf (gethash parent *attribute-plist*) k)))
                      ((getf (gethash parent *attribute-plist*) k)
                       (break "duplicate attribute ~s (~s was ~s) on ~s~%~s"
                              k v (getf (gethash parent *attribute-plist*) k)
                              (namespaced-name/s parent)
                              parent))
                      (t (setf (getf (gethash parent *attribute-plist*) k) v)))))
  (loop for i across (get-table header 'constant)
        do (assert (not (gethash (constant-parent i) *constant-index*)))
           (setf (gethash (constant-parent i) *constant-index*) i))
  (loop for i across (get-table header 'impl-map)
        do (assert (not (gethash (impl-map-member-forwarded i) *impl-map-index*)))
           (setf (gethash (impl-map-member-forwarded i) *impl-map-index*) i))
  (loop for i across (get-table header 'interface-impl)
        ;; not sure this ever has more than 1, but allow for it just
        ;; in case?
        do (push i (gethash (interface-impl-class i) *interface-impl-index*)))
  ;; 2 indices for nested-class, so we can skip nested from top level
  ;; and find nested from enclosing
  (loop
    for i across (get-table header 'nested-class)
    do (assert (not (gethash (nested-class-nested-class i) *nested-class-index*)))
       (setf (gethash (nested-class-nested-class i) *nested-class-index*) i)
       (push i (gethash (nested-class-enclosing-class i)
                        *enclosing-class-index*)))
  (loop for i across (get-table header 'type-def)
        for sa = (getf (gethash i *attribute-plist*) :supported-architecture)
        do (when (or (not sa)
                     ;; if type-def is for specific architecture(s),
                     ;; only add it to index if it is the architecture
                     ;; we currently care about
                     (member *architecture* sa))
             (unless (or (type-def-type-namespace i)
                         (string= (type-def-type-name i) "<Module>"))
               (assert (gethash i *nested-class-index*)))
             (when (type-def-type-namespace i)
               (setf (gethash (list (type-def-type-namespace i)
                                    (type-def-type-name i))
                              *type-def-by-name*)
                     i))
             ;; add namespace name nested-name for nested classes
             ;; without namespace so we can resolve type-refs for
             ;; anonymous nested classes
             (loop for nc in (gethash i *enclosing-class-index*)
                   for n = (nested-class-nested-class nc)
                   unless (type-def-type-namespace n)
                     do (setf (gethash (list (type-def-type-namespace i)
                                             (type-def-type-name i)
                                             (type-def-type-name n))
                                       *type-def-by-name*)
                              n)))
           ;; not sure we need this, but might be interesting to add a list of
           ;; subclasses (as a comment maybe?)
           (push i (gethash (type-def-extends i) *extends-index*))))


(defvar *in-type-def* nil)
(defvar *in-enum* nil)

(defvar *seen* (make-hash-table))

(defun see (type)
  (incf (gethash type *seen* 0))
  (when (typep type 'type-ref)
    (incf (gethash (type-ref-resolution-scope type) *seen* 0))))

(defmethod dump :around (x)
  (let ((r (call-next-method)))
    (when r
      (when (gethash x *seen* nil)
        (break "dupe ~s ~s~%~s"
               (not (not (gethash x *nested-class-index*)))
               *in-type-def*
               x))
      (see x))
    r))

(defmethod dump ((x null)) nil)
(defmethod dump ((x vector))
  (remove nil (map 'list 'dump x)))

(defmethod dump ((x custom-attribute))
  ;; dump as a plist of attributes to be spliced into parent?
  )

(defmethod dump ((x interface-impl))
  (see (interface-impl-interface x))
  (namespaced-name (interface-impl-interface x)))

(defmethod dump ((x blob-signature))
  (labels ((ptype (sig)
             (destructuring-bind (&key type value-type array ptr class
                                    rank sizes low)
                 sig
               (declare (ignorable ptr))
               (flet ((ptr? (x)
                        (loop repeat (count :ptr sig)
                              do (setf x (list :pointer x)))
                        #++(when (> (count :ptr sig) 1)
                             (let ((*print-level* 8))
                               (format t "~s~%" x)))
                        x))
                 (ptr?
                  (cond
                    ((and value-type (not type))
                     (when (and
                            (typep value-type 'type-ref)
                            (not
                             (or
                              (and (not (type-ref-type-namespace value-type)))
                              (member
                               (name (type-ref-resolution-scope
                                      value-type))
                               '("netstandard"
                                 "Windows.Win32.winmd"
                                 "Windows.Win32.System.Kernel")
                               :test 'string=))))
                       (break "~s? " value-type))
                     (see value-type)
                     (namespaced-name value-type))
                    ((and type (not value-type))
                     (assert (keywordp type))
                     ;; possibly should translate these? leaving as
                     ;; :i1,:u4, etc for now though
                     type)
                    ((and array (not value-type) (not type) (not class))
                     (list :array
                           :type (ptype array)
                           :rank rank
                           :sizes sizes
                           :low-bounds low))
                    ((and class (not value-type) (not type) (not array))
                     (see class)
                     (namespaced-name class))
                    (t
                     (break "ft~% type ~s~% value-type ~s" type value-type))))))))

    (ecase (blob-signature-flags-conv x)
      (:field
       ;; assuming single value in PARAM for now
       (assert (not (blob-signature-gen-param-count x)))
       (assert (not (blob-signature-return-type x)))
       (assert (= 1 (blob-signature-param-count x)))
       (ptype (aref (blob-signature-param x) 0)))
      ;; method calling conventions
      ((:default :c :stdcall :thiscall :fastcall :vararg)
       ;; not supported for now
       (assert (not (blob-signature-gen-param-count x)))
       (let ((*print-level* 8))
         (append
          (list :calling-convention (blob-signature-flags-conv x))
          (when (blob-signature-flags-p x :has-this)
            (list :has-this t))
          (when (blob-signature-flags-p x :explicit-this)
            (list :explicit-this t))
          (list :return-type (ptype (blob-signature-return-type x))
                :param-types (map 'list #'ptype (blob-signature-param x)))))))))


(defmethod dump ((x field))
  (let ((opt nil)
        (layout (gethash x *layout-index*))
        (constant (gethash x *constant-index*)))
    (setf opt (loop for i in (gethash x *attribute-index*)
                    append (dump i)))
    (when layout
      (see layout)
      (setf (getf opt :offset) (field-layout-offset layout)))
    (when constant
      (assert (= 1 (length constant)))
      (setf constant (car constant))
      (see constant)
      (setf (getf opt :constant) (constant-value constant)))
    ;; skip :type field when dumping values from an enum if they match
    ;; the enum, to save some space
    (let ((type (dump (field-signature x))))
      (unless (and *in-enum*
                   (equal type (namespaced-name *in-type-def*)))
        (setf (getf opt :type) type)))
    (list* :name (field-name x)
           :flags (field-attributes-as-keys (field-flags x))
           opt)))

(defmethod dump ((x param))
  (let ((opt nil))
    (setf opt (loop for i in (gethash x *attribute-index*)
                    append (dump i)))
    (list* :name (param-name x)
           :flags (param-attributes-as-keys (param-flags x))
           :sequence (param-sequence x)
           opt)))

(defmethod dump ((x method-def))
  (let ((opt nil)
        (forward (gethash x *impl-map-index*)))
    (setf opt (loop for i in (gethash x *attribute-index*)
                    append (dump i)))
    (when forward
      (see forward)
      (setf (getf opt :mapping-flags) (p-invoke-attributes-as-keys
                                       (impl-map-mapping-flags forward)))
      (setf (getf opt :import-name) (impl-map-import-name forward))
      (see (impl-map-import-scope forward))
      (setf (getf opt :import-dll) (module-ref-name
                                    (impl-map-import-scope forward))))
    (list* :name (method-def-name x)
           :flags (method-attributes-as-keys (method-def-flags x))
           :impl-flags (method-impl-attributes-as-keys
                        (method-def-impl-flags x))
           :rva (method-def-rva x)
           ;; todo: merge info from sig and params
           :type (dump (method-def-signature x))
           :params (map 'list 'dump (method-def-param-list x))
           opt)))


(defmethod dump ((x type-def))
  (unless (or
           ;; don't dump types from "Windows.Win32.Foundation.Metadata"
           #++(string= (type-def-type-namespace x)
                       "Windows.Win32.Foundation.Metadata")
           (and
            ;; don't dump nested classes at top level
            (gethash x *nested-class-index*)
            ;; but dump them if we are inside enclosing-class
            (not *in-type-def*)))
    (when *in-type-def*
      (assert (eql *in-type-def*
                   (nested-class-enclosing-class
                    (gethash x *nested-class-index*)))))
    (let ((*in-type-def* x)
          (*in-enum* nil)
          (layout (gethash x *layout-index*))
          (att)
          (opt))
      (setf att (loop for i in (gethash x *attribute-index*)
                      append (dump i)))
      (when (getf att :flag-p)
        (setf *in-enum* t))
      (flet ((opt (x v)
               (when v
                 (setf (getf opt x) v))))
        (opt :nested-classes (map 'list
                                  (a:compose 'dump 'nested-class-nested-class)
                                  (gethash x *enclosing-class-index*)))
        (opt :methods (map 'list 'dump (type-def-method-list x)))
        (opt :fields (map 'list 'dump (type-def-field-list x)))
        (opt :implements (loop for i in (gethash x *interface-impl-index*)
                               collect (dump i)))
        (opt :extends (namespaced-name (type-def-extends x)))
        (setf opt (append att opt))
        (when layout
          (see layout)
          (setf (getf opt :packing-size) (class-layout-packing-size layout))
          (setf (getf opt :class-size) (class-layout-class-size layout)))
        (opt :flags (type-attributes-as-keys (type-def-flags x))))
      (map nil 'see (gethash x *enclosing-class-index*))

      (when (type-def-extends x)
        (see (type-def-extends x)))
      (list* :type-def
             :name (namespaced-name x)
             opt))))

(defun get-sig-param-type-info (param &key update-path enum (deref t))
  (labels ((get-type (type)
             ;; direct check first so we can put type-refs there if
             ;; needed
             (or (gethash type *type-def-info*)
                 (progn
                   (assert type)
                   (cond
                     (deref
                      (when (typep type 'type-ref)
                        (let ((new (gethash
                                    (if (type-ref-type-namespace type)
                                        (list (type-ref-type-namespace type)
                                              (type-ref-type-name type))
                                        (list (type-ref-type-namespace
                                               (type-ref-resolution-scope type))
                                              (type-ref-type-name
                                               (type-ref-resolution-scope type))
                                              (type-ref-type-name type)))
                                    *type-def-by-name*
                                    type)))
                          (assert (not (eql type new)))
                          (setf type new)))
                      (assert (not (typep type 'type-ref)))
                      (if update-path
                          (update-type-def-size type :path update-path)
                          (let ((r (gethash type *type-def-info*)))
                            (assert r)
                            r)))
                     (t
                      type)))))

           (type-from-sig-param (param &key enum)
             (let ((type (or (getf param :type)
                             (getf param :value-type))))
               (when enum
                 (assert (not (getf param :ptr)))
                 (assert (not (getf param :array)))
                 (assert (member type '(:u1 :i1 :u2 :i2 :u4 :i4 :u8 :i8))))
               (cond
                 ((getf param :ptr)
                  (gethash :ptr *type-def-info*))
                 ((getf param :class)
                  ;; :class in structs is a pointer?
                  (gethash :ptr *type-def-info*))
                 ((getf param :array)
                  (destructuring-bind (&key array rank sizes low) param
                    (assert (not type))
                    ;; todo: support more shapes, low bounds, etc?
                    (assert (= 1 rank))
                    (assert (= 1 (length sizes)))
                    (assert (= 1 (length low)))
                    (assert (zerop (elt low 0)))
                    (destructuring-bind (s a b)
                        (if (or (getf array :ptr) (getf array :class))
                            (gethash :ptr *type-def-info*)
                            (get-type
                             (or (getf array :type)
                                 (getf array :value-type))))
                      (assert (and s a b))
                      (list (* s (elt sizes 0)) a `(:array ,b)))))
                 (t (assert (get-type type))
                    (get-type type))))))
    (type-from-sig-param param :enum enum)))

(defun get-field-type-info (field &key update-path enum)
  (let* ((sig (field-signature field))
         (params (blob-signature-param sig))
         (param (aref params 0)))
    (assert (= 1 (length params)))
    (get-sig-param-type-info param :update-path update-path :enum enum)))

(defun update-type-def-size (x &key path)
  (unless (or (gethash x *type-def-info*)
              ;; ignore some types used by the metadata format
              (string= (type-def-type-namespace x)
                       "Windows.Win32.Foundation.Metadata")
              (let ((sa (getf (gethash x *attribute-plist*) :supported-architecture)))
                (when (and sa (not (member *architecture* sa))
                           (string= (name x) "MEMORY_BASIC_INFORMATION"))
                  #++(break "drop ~s ~s~% ~s"
                            sa (namespaced-name/s x)
                            (gethash x *attribute-plist*))
                  (format t "drop ~s ~s~%"
                          sa (namespaced-name/s x)))
                (and sa (not (member *architecture* sa)))))
    (labels ((align (value alignment)
               (* alignment (ceiling value alignment)))
             (gfti (f)
               (get-field-type-info
                f :update-path (if (type-def-type-namespace x)
                                   (list (type-def-type-namespace x)
                                         (type-def-type-name x))
                                   (append path (list (type-def-type-name x)))))))
      (case (type-def-flags x)
        ;; top-level meta-types that we can ignore for this
        (0
         (assert (string= (name x) "<Module>")))
        (#x00120181
         (assert (string= (type-def-type-name x) "Apis")))
        ;; enums and delegates
        ((#x00000101 #x00120101 #x00004101)
         (cond
           ((ns-equal (type-def-extends x) "System" "Enum")
            ;; find base type of enum and copy info from that
            (let* ((f (aref (type-def-field-list x) 0))
                   (size (get-field-type-info f :enum t))
                   #++(size (type-from-sig (field-signature f) :enum t)))
              (assert (string= (field-name f) "value__"))
              (assert size)
              (setf (gethash x *type-def-info*) size))
            (assert (zerop (length (type-def-method-list x))))
            (assert (zerop (length (gethash x *enclosing-class-index*))))
            (when (zerop (length (type-def-field-list x)))
              (break "enum ~s has 0 fields?" (namespaced-name x))))
           ((ns-equal (type-def-extends x) "System" "MulticastDelegate")
            ;;function pointers?
            (setf (gethash x *type-def-info*) (gethash :ptr *type-def-info*)))
           (t
            (break "unexpected base type?~% ~s~%extends~% ~s"
                   (namespaced-name/s x)
                   (namespaced-name/s (type-def-extends x))))))
        ;; actual types
        (t
         (cond
           ;; com types?
           ((null (type-def-extends x))
            ;; these might just be pointers? ignoring for now since
            ;; they don't seem to appear in other structs
            )
           ;; structs and unions
           ((ns-equal (type-def-extends x) "System" "ValueType")
            (let ((offset 0)
                  (align 0)
                  (size 0))
              (loop for f across (type-def-field-list x)
                    for fl = (gethash f *layout-index*)
                    for ft = (gfti f)
                    ;;for ft = (type-from-sig (field-signature f))
                    for (s a b) = ft
                    do (unless ft
                         (break "no size for slot ~s?" (field-name f)))
                       (setf align (max align a))
                       (if fl
                           (setf offset (field-layout-offset fl))
                           (setf offset (align offset a)))
                       (assert (zerop (mod offset a)))
                       (incf offset s)
                       (setf size (max size offset)))
              (setf (gethash x *type-def-info*)
                    (list size align x))))
           (t
            (break "unexpected base type?~% ~s~%extends~% ~s"
                   (namespaced-name/s x)
                   (namespaced-name/s (type-def-extends x)))))))))
  ;; return size so we can call this to query size and update it if
  ;; needed in 1 step
  (gethash x *type-def-info*))

(defun update-type-def-sizes (file)
  (let ((table (get-table file 'type-def)))
    (reset-type-def-info file)
    (map 'nil 'update-type-def-size table)))

;; todo: make these name translations generic, so we can have
;; different sets for different purposes
(defun translate-namespace-for-ffi (x)
  (let ((ns (if (stringp x) x (namespace x))))
    ;; todo: split by #\., MixedCase -> MIXED-CASE, rejoin with #\.
    ns))

(defun translate-enum-name-for-ffi (x parent flag-p)
  (declare (ignore parent flag-p))
  (let ((name (if (stringp x) x (name x))))
    ;; todo: pfxMixedFOOCase12 -> PFX-MIXED-FOO-CASE-12
    name))

(defun translate-function-name-for-ffi (x)
  (let ((name (if (stringp x) x (namespaced-name/s x))))
    ;; todo: pfxMixedFOOCase12 -> PFX-MIXED-FOO-CASE-12
    name))

(defun translate-dll-name-for-ffi (x)
  (subseq x 0 (search ".dll" x)))

(defun translate-slot-name-for-ffi (x)
  (let ((name (if (stringp x) x (name x))))
    ;; todo: pfxMixedFOOCase12 -> PFX-MIXED-FOO-CASE-12
    name))

(defun translate-arg-name-for-ffi (x)
  (let ((name (if (stringp x) x (name x))))
    ;; todo: pfxMixedFOOCase12 -> PFX-MIXED-FOO-CASE-12
    name))

(defun translate-type-name-for-ffi (x)
  (cond
    ((member x '(:u1 :i1 :u2 :i2 :u4 :i4 :u8 :i8 :r4 :r8 :ptr :string
                 :char :boolean :u :i))
     (third (gethash x *base-types*)))
    (t
     (let ((name (if (stringp x)
                     x
                     (namespaced-name/s x))))
       ;; todo: pfxMixedFOOCase12 -> PFX-MIXED-FOO-CASE-12
       name))))

(defun translate-struct-name-for-ffi (x)
  (translate-type-name-for-ffi x))

(defun translate-interface-name-for-ffi (x)
  (translate-type-name-for-ffi x))

(defun translate-enum-type-name-for-ffi (x flag)
  (declare (ignore flag))
  (translate-type-name-for-ffi x))


(defun resolve-type-ref (x)
  (typecase x
    (type-ref
     (let ((other (if (type-ref-type-namespace x)
                      (gethash (list (type-ref-type-namespace x)
                                     (type-ref-type-name x))
                               *type-def-by-name*)
                      (let ((s (type-ref-resolution-scope x)))
                        (gethash (list (type-ref-type-namespace s)
                                       (type-ref-type-name s)
                                       (type-ref-type-name x))
                                 *type-def-by-name*)))))
       (unless other
         (break "couldn't resolve type ref~% ~s?~% in ~s~%"
                (namespaced-name/s x)
                (namespaced-name/s (type-ref-resolution-scope x))))
       other))
    (t x)))

(defun expand-struct/union-slots (x)
  (destructuring-bind (size align base) (gethash x *type-def-info*)
    (assert (and size align base))
    (let ((nested-types (make-hash-table :test 'equalp)))
      (flet ((align (x a)
               (* a (ceiling x a)))
             (array-size (sig)
               (when (getf sig :array)
                 (destructuring-bind (&key array rank sizes low) sig
                   (declare (ignore array))
                   ;; todo: arrays with low bounds? (probably not needed
                   ;; for winmd files?)
                   (assert (every 'zerop low))
                   ;; todo: arrays like foo[12][34][][]
                   (assert (= (length sizes) rank))
                   (list :count (reduce '* sizes)))))
             (nested-anonymous (pt)
               (let* ((vt (getf pt :value-type)))
                 ;; we have a type-ref
                 (when (and vt (typep vt 'type-ref)
                            ;; actual type, not a pointer to it
                            (not (getf pt :ptr))
                            ;; to a type nested in this one
                            (or (eql (type-ref-resolution-scope vt) x)
                                ;; or a ref to this one
                                (ns-equal (type-ref-resolution-scope vt)
                                          (type-def-type-namespace x)
                                          (type-def-type-name x))))
                   (gethash (type-ref-type-name vt) nested-types)))))
        (loop for nc in (gethash x *enclosing-class-index*)
              for i = (nested-class-nested-class nc)
              do (multiple-value-bind (slots)
                     (expand-struct/union-slots i)
                   (setf (gethash (type-def-type-name i) nested-types)
                         slots)))
        (loop with offset = 0
              for f across (type-def-field-list x)
              for sig = (aref (blob-signature-param (field-signature f)) 0)
              for (fs fa ft) = (get-field-type-info f)
              for na = (nested-anonymous sig)
              for fl = (gethash f *layout-index*)
              when fl
                do (setf offset (field-layout-offset fl))
              else do (setf offset (align offset fa))
              when na
                append (loop for (sn st . sk) in na
                             for (an nn) = (multiple-value-list
                                            (a:starts-with-subseq
                                             "Anonymous" (field-name f)
                                             :return-suffix t))
                             do (incf (getf sk :offset) offset)
                             collect (list* (if (and an
                                                     (every 'digit-char-p
                                                            nn))
                                                sn
                                                (format nil "~a.~a"
                                                        (field-name f)
                                                        sn))
                                            st sk))
              else
                collect `(,(name f)
                          ,(if (typep ft '(cons (eql :array)))
                               (translate-type-name-for-ffi (second ft))
                               (translate-type-name-for-ffi ft))
                          ,@(array-size sig)
                          :offset ,offset)
              do (incf offset fs))))))



(defmethod gen-cffi :around ((x type-def) &key)
  ;; filter out some types used by the metadata format
  (unless (equal (type-def-type-namespace x)
                 "Windows.Win32.Foundation.Metadata")
    (call-next-method)))

(defmethod gen-cffi ((x type-def) &key nested in-flag)
  (declare (ignorable nested in-flag))
  (unless (or ;; ignore some types used by the metadata format
           (string= (type-def-type-namespace x)
                    "Windows.Win32.Foundation.Metadata")
           (let ((sa (getf (gethash x *attribute-plist*) :supported-architecture)))
             (when (and sa (not (member *architecture* sa))
                        (string= (name x) "MEMORY_BASIC_INFORMATION"))
               (format t "drop ~s ~s~%"
                       sa (namespaced-name/s x)))
             (and sa (not (member *architecture* sa)))))
    (case (type-def-flags x)
      (0 ;; module?
       (assert (string= (type-def-type-name x) "<Module>")))
      (#x00120181 ;; global namespace def
       ;; (:BEFORE-FIELD-INIT :AUTO-CLASS :SEALED :ABSTRACT :CLASS
       ;; :AUTO-LAYOUT :PUBLIC)
       (assert (string= (type-def-type-name x) "Apis"))
       (format t "~&todo: global namespace:~% ~a::~a~% ~s fields~% ~s methods~% ~s nested class~%extends ~a~%"
               (type-def-type-namespace x) (type-def-type-name x)
               (length (type-def-field-list x))
               (length (type-def-method-list x))
               (length (gethash x *enclosing-class-index*))
               (when (type-def-extends x)
                 (let ((ns (namespaced-name (type-def-extends x))))
                   (if ns
                       (format nil "~a::~a" (getf ns :namespace) (getf ns :name))
                       (name (type-def-extends x))))))
       (when (gethash x *enclosing-class-index*)
         (break "global namespace:~% ~a::~a~% ~s fields~% ~s methods~% ~s nested class~%extends ~a"
                (type-def-type-namespace x) (type-def-type-name x)
                (length (type-def-field-list x))
                (length (type-def-method-list x))
                (length (gethash x *enclosing-class-index*))
                (when (type-def-extends x)
                  (let ((ns (namespaced-name (type-def-extends x))))
                    (if ns
                        (format nil "~a::~a" (getf ns :namespace) (getf ns :name))
                        (name (type-def-extends x)))))))
       ;; just dump fields as constants for now.
       (loop for f across (type-def-field-list x)
             for att = (gethash f *attribute-plist*)
             for fl = (gethash f *layout-index*)
             for fc = (gethash f *constant-index*)
             for fca = (getf att :constant)
             for has-constant = (or fc fca)
             for guid = (getf att :guid)
             for docs = (getf att :documentation)
             for param = (aref (blob-signature-param
                                (field-signature f))
                               0)
             for type = (or (getf param :ptr)
                            (getf param :type)
                            (getf param :value-type))
             do (when docs
                  (format t "~&~%;; ~a~%" docs))
                (when (and fc fca)
                  (break "multiple constants for field ~s?~%constant= ~s~%att=~s"
                         (namespaced-name/s f)
                         (constant-value fc) fca))
                (if fc
                    (setf fc (constant-value fc))
                    (setf fc fca))
                (remf att :guid)
                (remf att :constant)
                (remf att :documentation)
                (cond
                  ((and has-constant (not fc) (not guid))
                   ;; interpretation depends on type
                   (cond
                     ((eql type :string)
                      (format t "(a:define-constant ~a ~s :test :string=)~@[;; ~{ ~s ~s~}~]~%"
                              (namespaced-name/s f)
                              ""
                              att))
                     (t (break "nil constant ~s~%~s"
                               (namespaced-name/s f)
                               (aref (blob-signature-param
                                      (field-signature f))
                                     0)))))
                  ((and fc (numberp fc) (not guid))
                   (format t "(defconstant ~a ~a)~@[;; ~{ ~s ~s~}~]~%"
                           (namespaced-name/s f)
                           fc
                           att))
                  ((and fc (stringp fc) (not guid))
                   (format t "(alexandria:define-constant ~a ~s :test 'string=)~@[;; ~{ ~s ~s~}~]~%"
                           (namespaced-name/s f)
                           fc
                           att))
                  ((and (not fc) guid)
                   (format t "(alexandria:define-constant ~a ~s :test 'string=)~@[;; ~{ ~s ~s~}~]~%"
                           (namespaced-name/s f)
                           (apply #'format nil "~8,'0x-~4,'0x-~4,'0x-~2,'0x~2,'0x-~@{~2,'0x~}"
                                  guid)
                           att))
                  ((and (typep type 'type-ref)
                        (ns-equal type "Windows.Win32.UI.Shell.PropertiesSystem"
                                  "PROPERTYKEY"))
                   (format t ";; ?? no value for ~s~%"
                           (namespaced-name/s f)))
                  (t (format t "?~s ~s~%" (not fc) guid)
                     (break "?~s~% ~s~% ~s~% ~s~%" fl fc att f))))
       ;; dump defcfun for methods
       (loop
         for m across (type-def-method-list x)
         for imp = (gethash m *impl-map-index*)
         for att = (gethash m *attribute-plist*)
         for params = (method-def-param-list m)
         for sig = (method-def-signature m)
         for sigparam = (blob-signature-param sig)
         for rt = (get-sig-param-type-info (blob-signature-return-type sig)
                                           :deref nil)
         for st = (map 'vector (a:rcurry 'get-sig-param-type-info
                                         :deref nil)
                       sigparam)
         for vararg = nil
         for conv = (ecase (blob-signature-flags-conv sig)
                      (:default nil)
                      (:vararg (setf vararg t) nil))
         do (unless (and (= (method-def-impl-flags m) 0)
                         (= (method-def-flags m) #x2096))
              (break "flags ~x = ~s~% ~x = ~s"
                     (method-def-impl-flags m)
                     (method-impl-attributes-as-keys
                      (method-def-impl-flags m))
                     (method-def-flags m)
                     (method-attributes-as-keys
                      (method-def-flags m))))
            (assert imp)
            (format t "~&~%(defcfun (~s :library ~a~@[ :convention ~a~])~%"
                    (translate-function-name-for-ffi
                     m)
                    (translate-dll-name-for-ffi
                     (module-ref-name (impl-map-import-scope imp)))
                    conv)
            ;; sometimes params has an entry for return type and
            ;; sometimes not (and there might be attributes on it if
            ;; it exists, so need to account for that if we start
            ;; handling things like :const or :not-null-terminated
            ;; automatically (or at least dump them into comments)
            (assert
             (or (= (length params) (length st))
                 (= (length params) (1+ (length st)))))
            (format t "~&   ~s" (translate-type-name-for-ffi
                                 (if (consp rt) (third rt) rt)))
            (loop for p across params
                  for seq = (param-sequence p)
                  for name = (param-name p)
                  for type = (unless (zerop seq)
                               (aref st (1- seq)))
                  for att = (gethash p *attribute-plist*)
                  for i = (when type
                            (translate-type-name-for-ffi
                             (if (consp type)
                                 (third type)
                                 type)))
                  for n = (when name
                            (translate-arg-name-for-ffi
                             name))
                  when att
                    do (format t "~&  ;;~{ ~s ~s~}~%" att)
                  unless (zerop seq)
                    do (format t "~&  (~s ~s)" n i))
            (when vararg (format t "~&  &rest"))
            (format t ")~%")))
      ((#x00000101 #x00120101 #x00004101)
       ;; enum, delegate, some classes used by metadata, WinRT enum or
       ;; delegate
       (cond
         ((ns-equal (type-def-extends x) "System" "Enum")
          ;; field: flag = #x601,name="value__" = enum type
          ;; field: flag = #x8056 = enum name constant:
          ;; parent=field = enum value CustomAttribute:
          ;; FlagsAttribute => bit flag
          (assert (ns-equal (type-def-extends x) "System" "Enum"))
          (assert (zerop (length (type-def-method-list x))))
          (assert (zerop (length (gethash x *enclosing-class-index*))))
          (when (zerop (length (type-def-field-list x)))
            (break "enum ~s has 0 fields?" (namespaced-name x)))

          (let* ((base-type (translate-type-name-for-ffi
                             (third (get-field-type-info
                                     (aref (type-def-field-list x) 0)))))
                 (flag-p (getf (gethash x *attribute-plist*) :flag-p))
                 (name `(,(translate-enum-type-name-for-ffi x flag-p)
                         ,base-type))
                 (slots (loop for f across (type-def-field-list x)
                              for cc = (gethash f *constant-index*)
                              for c = (when cc (constant-value cc))
                              unless (string= (field-name f) "value__")
                                collect `(,c ,(translate-enum-name-for-ffi
                                               f x flag-p))))
                 r)
            (if flag-p
                (setf r
                      `(cffi:defbitfield ,name ,@slots))
                (setf r `(cffi:defcenum ,name ,@slots)))
            (let ((*print-level* nil))
              (format t "~&~s~%" r))
            r))

         ((ns-equal (type-def-extends x) "System" "MulticastDelegate")
          (assert (zerop (length (type-def-field-list x))))
          (assert (= 2 (length (type-def-method-list x))))
          (assert (zerop (length (gethash x *enclosing-class-index*))))
          (assert (string= (method-def-name (aref (type-def-method-list x) 0))
                           ".ctor"))
          (assert (string= (method-def-name (aref (type-def-method-list x) 1))
                           "Invoke"))
          (let* ((invoke (aref (type-def-method-list x) 1))
                 (param (method-def-param-list invoke))
                 (sig (method-def-signature invoke))
                 (rt (get-sig-param-type-info (blob-signature-return-type sig)
                                              :deref nil)))
            (format t "~&~%")
            (unless (and (member (method-def-flags invoke)
                                 '(#x1c6))
                         (member (method-def-impl-flags invoke)
                                 '(#x3))
                         (member (blob-signature-flags
                                  (method-def-signature invoke))
                                 '(#x20)))
              (format t ";; ~x ~s~%"
                      (method-def-flags invoke)
                      (method-attributes-as-keys
                       (method-def-flags invoke)))
              (format t ";; ~x ~s~%"
                      (method-def-impl-flags invoke)
                      (method-impl-attributes-as-keys
                       (method-def-impl-flags invoke)))
              (format t ";; ~x ~s~%"
                      (blob-signature-flags
                       (method-def-signature invoke))
                      (signature-flags-as-keys
                       (blob-signature-flags
                        (method-def-signature invoke))))
              (break "delegate ~s~%" x))
            (unless (a:emptyp param)
              (loop for i from (param-sequence (aref param 0))
                    for p across param
                    for seq = (param-sequence p)
                    for name = (param-name p)
                    for s = (unless (zerop seq)
                              (aref (blob-signature-param sig) (1- seq)))
                    for type = (when s
                                 (get-sig-param-type-info s :deref nil))
                    for att = (gethash p *attribute-plist*)
                    when (or att (not (zerop seq)))
                      do (format t ";; (~s ~s)~@[~{ ~s ~s~}~]~%"
                                 name
                                 (translate-type-name-for-ffi
                                  (if (consp type) (third type) type))
                                 att)
                    do (assert (= i seq))))
            (format t ";;  -> ~s~%"
                    (translate-type-name-for-ffi
                     (if (consp rt) (third rt) rt)))
            (format t "(defctype ~s (:pointer))~%"
                    (translate-type-name-for-ffi (type-def-type-name x))))
          (when (position #\` (type-def-type-name x))
            (break "todo parameterized delegate ~s"
                   (namespaced-name x))
            ;; = parameterized delegate
            ;;  adds row(s) in generic-param table specifying generic types
            )
          (format t "todo: generate ffi for delegates/function pointers ~s~%"
                  (namespaced-name/s x)))
         (t (error "unexpected base type ~s?"
                   (namespaced-name (type-def-extends x))))))
      ((#x0010010A #x00100112) ;; nested struct/union
       ;; we ignore nested struct/union here, and expand them inline
       ;; into parent for generated ffi, since nothing else could be
       ;; using the type even if it were accessible as a whole (and
       ;; people can use cffi:foreign-slot-pointer to the first element
       ;; if they did need to access it as a whole.) may or may not
       ;; generate a slot for the whole nested struct, don't know yet.
       (assert (gethash x *nested-class-index*)))
      ((#x00100109 #x00100111 #x4109) ;; struct, union, winrt struct
       (assert (ns-equal (type-def-extends x) "System" "ValueType"))
       (assert (zerop (length (type-def-method-list x))))
       (format t "~&~%~s~%"
               `(cffi:defcstruct ,(format nil "~a::~a"
                                          (translate-namespace-for-ffi x)
                                          (translate-struct-name-for-ffi x))
                  ,@ (expand-struct/union-slots x))))
      ((#x000000A1 #x40a1 #x40a0) ;; interface
       (assert (zerop (length (type-def-field-list x))))
       (let ((r `(org.shirakumo.com-on:define-comstruct
                     ,(translate-interface-name-for-ffi x)
                   ,@ (loop
                        for m across (type-def-method-list x)
                        for sig = (blob-signature-param
                                   (method-def-signature m))
                        for params = (method-def-param-list m)
                        for rt = (get-sig-param-type-info
                                  (blob-signature-return-type
                                   (method-def-signature m))
                                  :deref nil)
                        for st = (map 'vector
                                      (a:rcurry 'get-sig-param-type-info
                                                :deref nil)
                                      sig)
                        do ;; sometimes params has an entry for return
                           ;; type and sometimes not (and there might
                           ;; be attributes on it if it exists, so
                           ;; need to account for that if we start
                           ;; handling things like :const or
                           ;; :not-null-terminated automatically (or
                           ;; at least dump them into comments)
                           (assert
                            (or (= (length params) (length st))
                                (= (length params) (1+ (length st)))))
                        collect `(,(translate-function-name-for-ffi m)
                                  ,(translate-type-name-for-ffi
                                    (if (consp rt) (third rt) rt))
                                  ,@(loop
                                      for p across params
                                      for seq = (param-sequence p)
                                      for name = (param-name p)
                                      for type = (unless (zerop seq)
                                                   (aref st (1- seq)))
                                      for att = (gethash p *attribute-plist*)
                                      for i = (when type
                                                (translate-type-name-for-ffi
                                                 (if (consp type)
                                                     (third type)
                                                     type)))
                                      for n = (when name
                                                (translate-arg-name-for-ffi
                                                 name))
                                      when att
                                        collect `(:comment ,seq ,@att)
                                      unless (zerop seq)
                                        collect (list n i)))))))
         (format t "~&~%~s~%" r)
         r))
      (t (break "unknown flag combination #x~8,'0x  in typedef~%~s~%~a::~a~%~s fields~%~s methods~%~s nested classes~% extends ~a"
                (type-def-flags x)
                (type-attributes-as-keys (type-def-flags x))
                (type-def-type-namespace x) (type-def-type-name x)
                (length (type-def-field-list x))
                (length (type-def-method-list x))
                (length (gethash x *enclosing-class-index*))
                (when (type-def-extends x)
                  (let ((ns (namespaced-name (type-def-extends x))))
                    (if ns
                        (format nil "~a::~a" (getf ns :namespace) (getf ns :name))
                        (name (type-def-extends x))))))))))

(defmacro with-winmd ((winmd-var filename &key (mmap t))
                      &body body)
  (alexandria:with-gensyms (a)
    (declare (ignorable a))
    `(let (,@(if mmap
                 `((,winmd-var (mmap:with-mmap (p fd size ,filename)
                                 (read-header (cffi:inc-pointer p *offset*)
                                              (- size *offset*)))))
                 `((,a (alexandria:read-file-into-byte-vector ,filename))
                   (,winmd-var (read-header ,a :start *offset*)))))
       (format t "done reading file ~s~%" (type-of ,winmd-var))
       (finish-output *standard-output*)
       (update-table-refs ,winmd-var)
       (update-indices ,winmd-var)
       (update-type-def-sizes ,winmd-var)
       ,@body)))

#++
(defparameter *file* (with-winmd (w #p"~/quicklisp/local-projects/3b-winmd/md/Windows.Win32.winmd") w))

#++
(with-winmd (w #p"~/quicklisp/local-projects/3b-winmd/md/Windows.Win32.winmd")
  (with-open-file (*standard-output*
                   #p"~/quicklisp/local-projects/3b-winmd/ffi.generated.lisp"
                   :direction :output :if-exists :supersede)
    (with-standard-io-syntax
      (let ((*print-pretty* t)
            (*print-readably* nil))
        (map nil 'gen-cffi (get-table w 'type-def))))
    nil))
#++
(with-winmd (w #p"~/quicklisp/local-projects/3b-winmd/md/Windows.Win32.winmd")
  (let ((*print-readably* nil)
        (*print-pretty* t))
    (map nil 'gen-cffi (get-table w 'type-def))))
