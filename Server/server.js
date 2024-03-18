require("dotenv").config();
const express = require("express");
const fs = require("fs");
const cors = require("cors");
const mariadb = require("mariadb");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const path = require("path");
const publicPath = path.join(__dirname, "upload");
const { v4: uuidv4 } = require("uuid"); // UUID 생성을 위한 라이브러리

//#############################################################
//###################    Setting Start   ######################
//#############################################################

const app = express();
const port = 4000;
const secretKey = process.env.SECRETKEY;

//=============================================================
// Cors Start
const corsOptions = {
  origin: process.env.ORIGIN,
};
// Cors End
//=============================================================

//=============================================================
// MariaDB 정보 설정 Start
const pool = mariadb.createPool({
  host: process.env.KSSA_DB_HOST,
  user: process.env.KSSA_DB_USER,
  password: process.env.KSSA_DB_PASSWORD,
  database: process.env.KSSA_DB_DATABASE,
});
// MariaDB 정보 설정 End
//=============================================================

// Helper function for replacer
const replacer = (key, value) =>
  typeof value === "bigint" ? value.toString() : value;

app.use(bodyParser.json());
app.use(cors({ origin: "*" }));

//=============================================================
// 미들웨어 함수를 사용하여 토큰 검증 Start
const verifyBearerToken = (req, res, next) => {
  const tokenHeader = req.headers["authorization"];
  const accessToken = tokenHeader && tokenHeader.split(" ")[1];
  if (!accessToken) {
    return (
      // .status(401)
      // .json({ error: "Unauthorized - Bearer token missing", RET_CODE: "0001" });
      res.json({
        error: "Unauthorized - Bearer token missing",
        RET_DATA: {},
        RET_CODE: "0001",
      })
    );
  }

  jwt.verify(accessToken, secretKey, (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .json({ error: "Token is not valid", RET_DATA: [], RET_CODE: "0001" });
    }

    req.user = decoded; // Attach user information to the request object
    next(); // Proceed to the next middleware
  });
};
// 미들웨어 함수를 사용하여 토큰 검증 End
//=============================================================

//=============================================================
// 보호된 엔드포인트 Start
app.post("/api/protected", verifyBearerToken, (req, res) => {
  res.json({ message: "Protected data", user: req.user });
});
// 보호된 엔드포인트 End
//=============================================================

//=============================================================
// 비밀번호 해시 생성, 검증 Start
async function hashPassword(password) {
  try {
    // 솔트 생성
    const salt = await bcrypt.genSalt(10); // 라운드 수를 조절 10

    // 비밀번호 해시 생성
    const hashedPassword = await bcrypt.hash(password, salt);

    return hashedPassword;
  } catch (error) {
    console.error("Error hashing password:", error);
    throw error;
  }
}

// 비밀번호 검증
async function verifyPassword(password, hashedPassword) {
  try {
    // 저장된 해시와 입력된 비밀번호를 비교하여 일치 여부를 반환
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    console.error("Error verifying password:", error);
    throw error;
  }
}
// 비밀번호 해시 생성, 검증 End
//=============================================================

//=============================================================
// 업로드된 파일을 저장할 디렉토리 설정 / 미들웨어 Start
const storage = multer.diskStorage({
  dest: "uploads/",
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueFileName = uuidv4(); // 고유한 파일 이름 생성
    const fileExtension = path.extname(file.originalname); // 파일 확장자 추출
    const fileName = `${uniqueFileName}${fileExtension}`; // 고유한 파일 이름에 확장자 추가
    // 파일을 저장할 절대 경로를 설정합니다.
    cb(null, fileName);
  },
});
// 업로드된 파일을 저장할 디렉토리 설정 / 미들웨어 End

//=============================================================

//#############################################################
//####################    Setting End   #######################
//#############################################################

//#############################################################
//####################    Common Start    #####################
//#############################################################
const upload = multer({ storage: storage }).array("files", 10); // 'files'는 클라이언트에서 전송한 필드명입니다.
// app.post("/FileUpload", verifyBearerToken, async (req, res) => {
app.post("/FileUpload", (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "파일 업로드에 실패했습니다." });
    }
    let conn;
    try {
      conn = await pool.getConnection();
      const files = req.files;
      const File_Key = uuidv4();
      for (const file of files) {
        const Original_FileName = file.originalname;
        const Save_FileName = file.filename;
        const File_Path = file.path;
        const File_Ext = file.originalname.split(".").pop();
        const File_Size = file.size;
        const File_query =
          "INSERT INTO NKSSA_FileAttach (File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size) VALUES (?, ?, ?, ?, ?, ? )";
        const result = await conn.query(File_query, [
          File_Key,
          Original_FileName,
          Save_FileName,
          File_Path,
          File_Ext,
          File_Size,
        ]);
      }
      res.json({
        RET_DATA: { FileKey: File_Key },
        RET_DESC: "파일 업로드에 성공했습니다.",
        RET_CODE: "0000",
      });
    } catch (error) {
      console.error("파일 저장 중 오류 발생:", error);
      res.json({
        RET_DATA: null,
        RET_DESC: `파일 업로드 실패_${err}`,
        RET_CODE: "1000",
      });
    }
  });
});

// app.post("/FileDelete", verifyBearerToken, async (req, res) => {
app.post("/FileDelete", async (req, res) => {
  const File_Idx = req.body.FileIdx;
  const File_Nm = req.body.FileNm;
  let conn;
  try {
    conn = await pool.getConnection();
    // 파일을 디스크에서 삭제
    fs.unlink(`uploads/${File_Nm}`, async (err) => {
      if (err) {
        console.error("파일 삭제 중 오류 발생:", err);
        return res
          .status(500)
          .json({ message: "파일 삭제 중 오류가 발생했습니다." });
      }
      // 데이터베이스에서 파일 정보 삭제
      const deleteFileQuery = "Delete From NKSSA_FileAttach Where Idx = ?";
      await conn.query(deleteFileQuery, [File_Idx]);

      res.json({
        RET_DATA: {},
        RET_DESC: "파일삭제 성공",
        RET_CODE: "0000",
      });
    });
  } catch (err) {
    console.error("파일 삭제 중 오류 발생:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `파일삭제 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
//#############################################################
//#####################    Common End    ######################
//#############################################################

//#############################################################
//#####################    USER Start   #######################
//#############################################################

//=============================================================
// 로그인 완료시 토큰 발행 Start
app.post("/User/Member_Login", async (req, res) => {
  const userid = req.body.userid;
  const userpw = req.body.userpw;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `Select User_Id, User_Nm, User_Pw FROM NKSSA_Members Where User_Id = ?`;
    const rows = await conn.query(query, [userid]);

    // 사용자가 존재하지 않는 경우
    if (rows.length === 0) {
      res.json({
        RET_DATA: null,
        RET_DESC: "입력하신 정보는 가입되어 있지 않습니다.",
        RET_CODE: "1000",
      });
    }
    const user = rows[0];
    const hashedPassword = user.User_Pw;
    // 입력된 비밀번호와 저장된 해시된 비밀번호 비교
    bcrypt.compare(userpw, hashedPassword, function (err, result) {
      if (err) {
        console.error("비밀번호를 체크하는 중에 오류가 발생했습니다.:", err);
        res.json({
          RET_DATA: null,
          RET_DESC: "비밀번호를 체크하는 중에 오류가 발생했습니다.",
          RET_CODE: "2000",
        });
      } else if (result) {
        // 비밀번호 일치
        const accessToken = jwt.sign(
          {
            User_Id: user.User_Id,
            User_Nm: user.User_Nm,
          },
          secretKey,
          { expiresIn: "1h" }
        );
        res.json({
          RET_DATA: {
            accessToken,
            User_Id: user.User_Id,
            User_Nm: user.User_Nm,
          },
          RET_DESC: "성공",
          RET_CODE: "0000",
        });
      } else {
        // 비밀번호 불일치
        console.error("입력하신 비밀번호가 맞지 않습니다.:", err);
        res.json({
          RET_DATA: null,
          RET_DESC: "입력하신 비밀번호가 맞지 않습니다.",
          RET_CODE: "2000",
        });
      }
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `로그인 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) await conn.end();
  }
});
// 로그인 완료시 토큰 발행 End
//=============================================================

//=============================================================
// 로그인한 회원 정보 Start
app.post("/User/Member_Info", verifyBearerToken, async (req, res) => {
  const UserId = req.user.userid;
  const UserNm = req.user.username;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select User_Id, User_Nm From NKSSA_Members Where User_Id = ? And User_Nm = ? ";
    const result = await conn.query(query, [UserId, UserNm]);

    res.json({
      RET_DATA: {
        User_Id: result[0].User_Id,
        User_Nm: result[0].User_Nm,
      },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// 로그인한 회원 정보 End
//=============================================================

//=============================================================
// 회원 등록 Start
app.post("/User/Member_Insert", async (req, res) => {
  const {
    User_Id,
    User_Pw,
    User_Type,
    Edu_Nm,
    Edu_Id,
    User_Nm,
    User_Phone,
    User_Email,
    User_Zip,
    User_Address,
    User_Address_Detail,
    Company_Nm,
    Company_Zip,
    Company_Address,
    Company_Address_Detail,
    Manager_Nm,
    Manager_Phone,
    Manager_Email,
  } = req.body;
  const hashedPassword = await hashPassword(req.body.User_Pw); // 비밀번호 해시 생성
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Insert Into NKSSA_Members (User_Id, User_Pw, User_Type, Edu_Nm, Edu_Id, User_Nm, User_Phone, User_Email, User_Zip " +
      ", User_Address, User_Address_Detail, Company_Nm, Company_Zip, Company_Address, Company_Address_Detail, Manager_Nm " +
      ", Manager_Phone, Manager_Email) " +
      "Values " +
      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      User_Id,
      hashedPassword,
      User_Type,
      Edu_Nm,
      Edu_Id,
      User_Nm,
      User_Phone,
      User_Email,
      User_Zip,
      User_Address,
      User_Address_Detail,
      Company_Nm,
      Company_Zip,
      Company_Address,
      Company_Address_Detail,
      Manager_Nm,
      Manager_Phone,
      Manager_Email,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    // if (conn) return conn.end();
    if (conn) conn.release();
  }
});
// 회원 등록 End
//=============================================================

//=============================================================
// 회원 정보 수정 Start
app.post("/User/Member_Update", verifyBearerToken, async (req, res) => {
  const {
    Edu_Nm,
    Edu_Id,
    User_Nm,
    User_Phone,
    User_Email,
    User_Zip,
    User_Address,
    User_Address_Detail,
    Company_Nm,
    Company_Zip,
    Company_Address,
    Company_Address_Detail,
    Manager_Nm,
    Manager_Phone,
    Manager_Email,
    Idx,
  } = req.body;

  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Members set Edu_Nm = ?, Edu_Id = ?, User_Nm = ?, User_Phone = ?, User_Email = ?, User_Zip = ? " +
      ", User_Address = ?, User_Address_Detail = ?, Company_Nm = ?, Company_Zip = ?, Company_Address = ?, Company_Address_Detail = ?, Manager_Nm = ? " +
      ", Manager_Phone = ?, Manager_Email = ? " +
      "Where Idx = ? ";
    const result = await conn.query(query, [
      Edu_Nm,
      Edu_Id,
      User_Nm,
      User_Phone,
      User_Email,
      User_Zip,
      User_Address,
      User_Address_Detail,
      Company_Nm,
      Company_Zip,
      Company_Address,
      Company_Address_Detail,
      Manager_Nm,
      Manager_Phone,
      Manager_Email,
      Idx,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// 회원 정보 수정 End
//=============================================================

//=============================================================
// Contens List Start
app.post("/User/Contets_List", async (req, res) => {
  const { Contents_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Contents From NKSSA_Contents Where Contents_Type = ? And State = '0' ";
    const result = await conn.query(query, [Contents_Type]);

    res.json({
      RET_DATA: { result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Contens List End
//=============================================================

//=============================================================
// Board List Start
app.post("/User/Board_List", async (req, res) => {
  const { Board_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Board_Type, Subject, Contents, Visited, InDate From NKSSA_Board Where Board_Type = ? And State = '0' ";
    const result = await conn.query(query, [Board_Type]);

    res.json({
      RET_DATA: result,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board List End
//=============================================================

//=============================================================
// Board View Start
app.post("/User/Board_View", async (req, res) => {
  const { Board_Type, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // 게시물 조회
    const query =
      "Select Board_Type, Subject, Contents, File_Key, Visited, InDate From NKSSA_Board Where Board_Type = ? And Idx = ?";
    const result = await conn.query(query, [Board_Type, Idx]);

    // 파일 조회
    const file_query =
      "Select File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size From NKSSA_FileAttach Where File_Key = ?";
    const file_result = await conn.query(file_query, [result[0].File_Key]);
    res.json({
      RET_DATA: { result, file_result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board View End
//=============================================================

//=============================================================
// Calender List Start
app.post("/User/Calender_List", verifyBearerToken, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, InDate From NKSSA_Calender";
    const result = await conn.query(query, []);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender List End
//=============================================================

//=============================================================
// Calender View Start
app.post("/User/Calender_View", verifyBearerToken, async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, InDate From NKSSA_Calender Where Idx = ?";
    const result = await conn.query(query, [Idx]);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender View End
//=============================================================

//#############################################################
//######################    USER End   ########################
//#############################################################

//#############################################################
//#####################     Adm Start   #######################
//#############################################################

//=============================================================
// 회원 List Start
app.post("/Adm/Member_List", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      " Select Idx, User_Id, User_Pw, User_Type, Edu_Nm, Edu_Id, User_Nm, User_Phone, User_Email, User_Zip, User_Address, User_Address_Detail " +
      " , Company_Nm, Company_Zip, Company_Address, Company_Address_Detail, Manager_Nm, Manager_Phone, Manager_Email, State, InDate " +
      " From NKSSA_Members ";
    const result = await conn.query(query, []);

    res.json({
      RET_DATA: result,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// 회원 List End
//=============================================================

//=============================================================
// Contens List Start
app.post("/Adm/Contets_List", async (req, res) => {
  const { Contents_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Contents From NKSSA_Contents Where Contents_Type = ? ";
    const result = await conn.query(query, [Contents_Type]);

    res.json({
      RET_DATA: { result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Contens List End
//=============================================================

//=============================================================
// Contents 등록 Start
app.post("/Adm/Contets_Insert", verifyBearerToken, async (req, res) => {
  const { Contents_Type, Contents } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Insert Into NKSSA_Contents (Contents_Type, Contents) " +
      "Values " +
      "(?, ?)";
    const result = await conn.query(query, [Contents_Type, Contents]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Contents 등록 End
//=============================================================

//=============================================================
// Contents 수정 Start
app.post("/Adm/Contets_Update", verifyBearerToken, async (req, res) => {
  const { Contents_Type, Contents, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Contents set Contents_Type = ?, Contents = ? " +
      "Where Idx = ? ";
    const result = await conn.query(query, [Contents_Type, Contents, Idx]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Contents 수정 End
//=============================================================

//=============================================================
// Board List Start
app.post("/Adm/Board_List", async (req, res) => {
  const { Board_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Board_Type, Subject, Contents, Visited, InDate From NKSSA_Board Where Board_Type = ? And State = '0' ";
    const result = await conn.query(query, [Board_Type]);

    res.json({
      RET_DATA: result,
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board List End
//=============================================================

//=============================================================
// Board View Start
app.post("/Adm/Board_View", async (req, res) => {
  const { Board_Type, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    // 게시물 조회
    const query =
      "Select Board_Type, Subject, Contents, File_Key, Visited, InDate From NKSSA_Board Where Board_Type = ? And Idx = ?";
    const result = await conn.query(query, [Board_Type, Idx]);

    // 파일 조회
    const file_query =
      "Select File_Key, Original_FileName, Save_FileName, File_Path, File_Ext, File_Size From NKSSA_FileAttach Where File_Key = ?";
    const file_result = await conn.query(file_query, [result[0].File_Key]);
    res.json({
      RET_DATA: { result, file_result },
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) return conn.end();
  }
});
// Board View End
//=============================================================

//=============================================================
// Board 등록 Start
app.post("/Adm/Board_Insert", verifyBearerToken, async (req, res) => {
  const { Board_Type, Subject, Contents, File_Key, InDate } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "INSERT INTO NKSSA_Board (Board_Type, Subject, Contents, File_Key, InDate) VALUES (?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      Board_Type,
      Subject,
      Contents,
      File_Key,
      InDate,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Board 등록 End
//=============================================================

//=============================================================
// Board 수정 Start
app.post("/Adm/Board_Update", verifyBearerToken, async (req, res) => {
  const { Subject, Contents, State, Idx, Board_Type } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Board set Subject = ?, Contents = ?, State = ? where Idx = ? and Board_Type = ?";
    const result = await conn.query(query, [
      Subject,
      Contents,
      State,
      Idx,
      Board_Type,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Board 수정 End
//=============================================================

//=============================================================
// Calender List Start
app.post("/Adm/Calender_List", verifyBearerToken, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, InDate From NKSSA_Calender";
    const result = await conn.query(query, []);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender List End
//=============================================================

//=============================================================
// Calender View Start
app.post("/Adm/Calender_View", verifyBearerToken, async (req, res) => {
  const { Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, InDate From NKSSA_Calender Where Idx = ?";
    const result = await conn.query(query, [Idx]);
    res.json({
      RET_DATA: result,
      RET_DESC: "조회 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `조회 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender View End
//=============================================================

//=============================================================
// Calender Insert Start
app.post("/Adm/Calender_Insert", verifyBearerToken, async (req, res) => {
  const {
    Edu_Nm,
    Edu_Type,
    Base_Line,
    Edu_Date_Start,
    Edu_Date_End,
    Edu_Personnel,
  } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "INSERT INTO NKSSA_Calender ( Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel ) VALUES (?, ?, ?, ?, ?, ?)";
    const result = await conn.query(query, [
      Edu_Nm,
      Edu_Type,
      Base_Line,
      `${Edu_Date_Start} 00:00:00`,
      `${Edu_Date_End} 00:00:00`,
      Edu_Personnel,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "저장 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `저장 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender Insert End
//=============================================================

//=============================================================
// Calender Update Start
app.post("/Adm/Calender_Update", verifyBearerToken, async (req, res) => {
  const {
    Edu_Nm,
    Edu_Type,
    Base_Line,
    Edu_Date_Start,
    Edu_Date_End,
    Edu_Personnel,
    Idx,
  } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Update NKSSA_Calender Set Edu_Nm = ?, Edu_Type = ?, Base_Line = ?, Edu_Date_Start = ?, Edu_Date_End = ?, Edu_Personnel = ? Where Idx = ?";
    const result = await conn.query(query, [
      Edu_Nm,
      Edu_Type,
      Base_Line,
      `${Edu_Date_Start} 00:00:00`,
      `${Edu_Date_End} 00:00:00`,
      Edu_Personnel,
      Idx,
    ]);
    res.json({
      RET_DATA: null,
      RET_DESC: "수정 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `수정 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender Update End
//=============================================================

//=============================================================
// Calender State처리 Start
app.post("/Adm/Calender_State", verifyBearerToken, async (req, res) => {
  const { Edu_State, Idx } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query = "Update NKSSA_Calender Set Edu_State = ? Where Idx = ?";
    const result = await conn.query(query, [Edu_State, Idx]);
    res.json({
      RET_DATA: null,
      RET_DESC: "상태처리 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `상태처리 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender State처리 End
//=============================================================

//=============================================================
// Calender List Start
app.post("/Adm/Calender_YearPlan", verifyBearerToken, async (req, res) => {
  const { YearPlan } = req.body;
  let conn;
  try {
    conn = await pool.getConnection();
    const query =
      "Select Idx, Edu_Nm, Edu_Type, Base_Line, Edu_Date_Start, Edu_Date_End, Edu_Personnel, InDate From NKSSA_Calender Where YEAR(Edu_Date_Start) = ? Order By Edu_Date_Start";
    const result = await conn.query(query, [YearPlan]);

    res.json({
      RET_DATA: result.map((row) => ({
        Idx: row.Idx,
        Edu_Nm: row.Edu_Nm,
        Edu_Type: row.Edu_Type,
        Base_Line: row.Base_Line,
        Edu_Date_SM: (1 + row.Edu_Date_Start.getMonth())
          .toString()
          .padStart(2, "0"),
        Edu_Date_SD: row.Edu_Date_Start.getDate().toString().padStart(2, "0"),
        Edu_Date_EM: (1 + row.Edu_Date_End.getMonth())
          .toString()
          .padStart(2, "0"),
        Edu_Date_ED: row.Edu_Date_End.getDate().toString().padStart(2, "0"),
        Edu_Personnel: row.Edu_Personnel,
        InDate: row.InDate,
      })),
      RET_DESC: "검색 완료",
      RET_CODE: "0000",
    });
  } catch (err) {
    console.error("Error executing MariaDB query:", err);
    res.json({
      RET_DATA: null,
      RET_DESC: `검색 실패_${err}`,
      RET_CODE: "1000",
    });
  } finally {
    if (conn) conn.release();
  }
});
// Calender List End
//=============================================================

//#############################################################
//######################     Adm End   ########################
//#############################################################

// 서버 시작
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
